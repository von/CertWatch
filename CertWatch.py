#!/usr/bin/env python
"""Monitor HTTPS sites for certificate changes"""
import argparse
import collections
import ConfigParser
import hashlib
import logging
import os.path
import sqlite3
import ssl
import subprocess
import sys

######################################################################

class DataBaseException(Exception):
    pass

class DataBase:

    TABLE_NAME = "CertWatchTable"

    def __init__(self, filename):
        self.filename = filename
        self.conn = sqlite3.connect(self.filename)
        self.cursor = self.conn.cursor()
        if not self.TABLE_NAME in self.__get_tables():
            self.__execute("create table " + self.TABLE_NAME + " " +
                           "( hostname text, fingerprint text, last_seen timestamp );")

    def __del__(self):
        self.__commit()
        self.cursor.close()
        self.conn.close()

    def __commit(self):
        self.conn.commit()

    def __execute(self, command, args=None):
        try:
            if args:
                self.cursor.execute(command, args)
            else:
                self.cursor.execute(command)                
        except sqlite3.OperationalError as e:
            raise DataBaseException("Error executing: " + command)
        return self.cursor.fetchall()

    def __get_tables(self):
        """Return list of tables in DB"""
        rows = self.__execute("SELECT name FROM sqlite_master WHERE type='table';")
        return [row[0] for row in rows]
        
    def add_service(self, service):
        """Add a service to the database"""
        self.__execute("insert into " + self.TABLE_NAME + " values (?,?,?)",
                       (service, "", 0))

    def get_service(self, service):
        rows = self.__execute("select * from " + self.TABLE_NAME + " where hostname=?", (service,))
        if len(rows) == 0:
            return None
        return Service(*rows[0])

    def get_services(self):
        """Return list of all services"""
        return [Service(*row) for row in self.__execute("select * from " + self.TABLE_NAME)]

    def update_service(self, service, fingerprint):
        self.__execute("update " + self.TABLE_NAME + " " +
                       "set fingerprint=? " +
                       "where hostname=?",
                       (fingerprint, service))

ServiceBase = collections.namedtuple("Service",
                                     ["hostname", "fingerprint", "last_seen"])

class Service(ServiceBase):

    def __str__(self):
        s = self.hostname
        if len(self.fingerprint):
            s += " ({})".format(self.fingerprint)
        return s

######################################################################
#
# Functions used by subcommands
#

def add_services(db, args):
    for service in args.services:
        if db.get_service(service) is None:
            args.output.info("Adding {}".format(service))
            db.add_service(service)
        else:
            args.output.info("Service {} already in database".format(service))

def list_services(db, args):
    args.output.debug("Listing services:")
    for service in db.get_services():
        print service

def scan_services(db, args):
    args.output.info("Scanning service...")
    for service in db.get_services():
        args.output.info("Checking {}".format(service.hostname))
        # TODO: Fix hard-coded port #
        cert_pem = ssl.get_server_certificate((service.hostname, 443))
        cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
        fingerprint = hashlib.sha1(cert_der).hexdigest()
        args.output.debug("Fingerprint is " + fingerprint)
        if len(service.fingerprint) == 0:
            args.output.info("First time scanned")
            db.update_service(service.hostname, fingerprint)
        elif service.fingerprint != fingerprint:
            args.output.info("Fingerprint has changed.")
            changed_fingerprint(service, fingerprint)
            db.update_service(service.hostname, fingerprint)
        else:
            args.output.debug("No change.")
        
        
######################################################################
#
# Utility functions
#

def changed_fingerprint(service, new_fingerprint):
    msg = "CHANGE: {} {} -> {}".format(service.hostname,
                                       service.fingerprint,
                                       new_fingerprint)
    subprocess.check_call(["twurl",
                           "-d",
                           "status=" + msg,
                           "/1/statuses/update.xml"])

def parse_args(argv, output):
    """Parse commandline arguments taking default from configuration file.

    If --conf_file is specified, it will be read and used to set defaults
    according to conf_mappings."""
    # Parse any conf_file specification
    # We make this parser with add_help=False so that
    # it doesn't parse -h and print help.
    conf_parser = argparse.ArgumentParser(
        # Turn off help, so we print all options in response to -h
        add_help=False
        )
    conf_parser.add_argument("-c", "--conf_file",
                        help="Specify config file", metavar="FILE")
    args, remaining_argv = conf_parser.parse_known_args(argv[1:])
    defaults = {
        "output_level" : logging.INFO,
        "database" : "./CertWatch.db",
        }
    if args.conf_file:
        # Mappings from configuraition file to options
        conf_mappings = [
            # ((section, option), option)
            (("Defaults", "option"), "option"),
            (("Database", "filename"), "database"),
            ]
        config = ConfigParser.SafeConfigParser()
        config.read([args.conf_file])
        for sec_opt, option in conf_mappings:
            if config.has_option(*sec_opt):
                value = config.get(*sec_opt)
                defaults[option] = value

    # Parse rest of arguments
    # Don't surpress add_help here so it will handle -h
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        parents=[conf_parser],
        # print script description with -h/--help
        description=__doc__,
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.set_defaults(**defaults)
    # Only allow one of debug/quiet mode
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-d", "--debug",
                                 action='store_const', const=logging.DEBUG,
                                 dest="output_level", 
                                 help="print debugging")
    verbosity_group.add_argument("-q", "--quiet",
                                 action="store_const", const=logging.WARNING,
                                 dest="output_level",
                                 help="run quietly")
    parser.add_argument("-f", "--log_file",
                        help="Log output to file", metavar="FILE")
    parser.add_argument("--option", help="some option")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    parser.add_argument("-D", "--database",
                        metavar="filename", help="specify database")

    subparsers = parser.add_subparsers()

    parser_add = subparsers.add_parser("add", help="add service")
    parser_add.set_defaults(command_function=add_services)
    parser_add.add_argument("services", metavar="hostnames", type=str,
			    nargs="+", help="services to add")
    
    parser_list = subparsers.add_parser("list", help="list services")
    parser_list.set_defaults(command_function=list_services)

    parser_scan = subparsers.add_parser("scan", help="scan services")
    parser_scan.set_defaults(command_function=scan_services)

    args = parser.parse_args(remaining_argv)
    args.output = output
    return args

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger(argv[0])
    output.setLevel(logging.DEBUG)
    output_handler = logging.StreamHandler(sys.stdout)  # Default is sys.stderr
    # Set up formatter to just print message without preamble
    output_handler.setFormatter(logging.Formatter("%(message)s"))
    output.addHandler(output_handler)

    args = parse_args(argv, output)
    
    output_handler.setLevel(args.output_level)
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(logging.Formatter("%(asctime)s:%(message)s"))
        output.addHandler(file_handler)
        output.debug("Logging to file {}".format(args.log_file))

    output.debug("Opening database {}".format(args.database))
    db = DataBase(args.database)

    result = args.command_function(db, args)
    return(result)

if __name__ == "__main__":
    sys.exit(main())
