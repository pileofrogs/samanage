#!/usr/bin/env python

import sys
import json
import urllib
import logging
import argparse
import requests
import inspect

'''
TODO: 
 - Handle awkward things with non-standard URIs
'''

class Record(object):
    def __init__(self, json_payload):
        self.id   = json_payload.get('id', None)
        self.name = json_payload.get('name', None)

    def __str__(self):
        return u'{}\n\t'.format(self.name) + '\n\t'.join([u'{}: {}'.format(k,v) 
            for k,v in self.__dict__.items() if v])

    def dump(self):
        return {k: v for k,v in self.__dict__.items() if v}

    def dumps(self):
        return json.dumps(self, 
                default=lambda o: {k: v for k,v in o.__dict__.items() if v})

def get_incidents(self, client):
    '''get a list of incidents using the client passed'''
    uri = '{}/hardwares/{}-{}/incidents.json'.format(
            client.uri, self.id, self.name.replace('.','-'))
    return client._get_raw(uri, 'incidents')

def record_factory ( obj_name, init_args={}, methods={}):
    '''creates classes for as-yet-undefined samanage record types'''
    def init ( self, payload ):
        init_args.update(payload)
        for key, value in init_args.items():
            setattr(self,key,value)
    methods['__init__'] = init
    return type( obj_name, (Record,),methods )

class Samanage(object):

    supported_types = {
            'incidents': record_factory('Incidents',methods = { 'get_incidents' : get_incidents }),
            }

    def __init__(self, username, password, uri='https://api.samanage.com'):
        self.username     = username
        self.password     = password
        self.uri          = uri
        self.logger       = logging.getLogger('samanage.Samanage')
        self.session      = requests.Session()
        self.session.auth = requests.auth.HTTPDigestAuth(
                self.username, self.password)
        self.session.headers = { 
                'Accept'       : 'application/vnd.samanage.v1.2+json',
                'Content-Type' : 'application/json',
                }
        self.logger.debug('Samanage obj created, credentials: {}/{}'.format(
            self.username, self.password))

    def _uri(self, record_type, record_id=None):
        if record_type not in self.supported_types:
            #raise ValueError('{} not supported'.format(record_type))
            self.supported_types[record_type] = record_factory(record_type.title())
        if record_id:
            return '{}/{}/{}.json'.format(self.uri, record_type, record_id) 
        return '{}/{}.json'.format(self.uri, record_type) 

    def _check_response(self, response, record_type):
        results = []
        if not response:
            self.logger.error('HTTP {}:{}'.format(
                response.status_code, response.text))
            response.raise_for_status()
            return response
        else:
            if response.text.strip():
                json_out = response.json()
                self.logger.debug(json.dumps(json_out, indent=4))
                self.logger.debug('Response Headers: {}'.format(response.headers))
                # any record_type _should_ (hah!) have been created during call to 
                # _uri earlier
                if type(json_out) is list:
                    for record in json_out:
                        results.append(self.supported_types.get(record_type, Record)(record))
                else:
                    results.append(
                            self.supported_types.get(record_type, Record)(json_out))
                return results
            else:
                return True

    def _get_raw(self, uri, record_type, record_id=None,count=None, pagesize=100, search=None):
        self.logger.debug('fetching uri:{}'.format(uri))    
        page=1
        data=[]
        while True:
            if count and len(data) + pagesize > count:
                pagesize = count - len(data)
            params={ 'per_page' : pagesize }
            if search:
                params.update(search)
            if page > 1: 
                params['page'] = page # how we tell samanage which page to get
            response = self.session.get(uri,params=params)
            checked = self._check_response(response, record_type)
            if len(checked) == 0: # no data, we're done
                break
            data.extend(checked)
            if len(checked) < pagesize: # no need for another run
                break
            if count and len(data) == count: # perfect 
                break
            if count and len(data) > count:
                raise Exception("Got too many records.  This should never happen.")
            page += 1
        return data

    def _payload(self, payload, record_type):
        if isinstance(payload, Record):
            return { record_type[:-1] : payload.dump() }
        return { record_type[:-1] : payload }

    def get(self, record_type, count=None, pagesize=100, record_id=None, search={}):
        #uri = self._get_uri(record_type, count, record_id, search)
        uri = self._uri(record_type, record_id)
        return self._get_raw(uri, record_type, count=count, pagesize=pagesize, search=search)

    def put(self, record_type, payload, record_id):
        if type(record_id) is not int:
            raise ValueError('record_id must by type int() not {}'.format(
                type(record_id)))
        uri = self._uri(record_type, record_id=record_id)
        response = self.session.put(uri, json=self._payload(payload, record_type))
        return self._check_response(response, record_type)

    def delete(self, record_type, record_id):
        if type(record_id) is not int:
            raise ValueError('record_id must by type int() not {}'.format(
                type(record_id)))
        uri = self._uri(record_type, record_id=record_id)
        response = self.session.delete(uri)
        return self._check_response(response, record_type)

    def post(self, record_type, payload):
        uri = self._uri(record_type)
        response = self.session.post(uri, json=self._payload(payload, record_type))
        return self._check_response(response, record_type)

def main():
    parser = argparse.ArgumentParser(description='dns spoof monitoring script')
    parser.add_argument('-u', '--username', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-T', '--type', required=True)
    parser.add_argument('-I', '--id', default=None)
    parser.add_argument('-U', '--uri', default='https://api.samanage.com',
            help='Sammanage api hendpoint')
    parser.add_argument('-S', '--search', default='{}', type=json.loads, 
            help='Search parameters as a hash')
    parser.add_argument('-C', '--count', default=25, 
            help='Number of entries to return')
    parser.add_argument('-v','--verbose', action="count")
    args = parser.parse_args()

    log_level = logging.ERROR
    if args.verbose == 1:
        log_level = logging.WARN
    elif args.verbose == 2:
        log_level = logging.INFO
    elif args.verbose > 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)
    logger = logging.getLogger('samanage.main')

    client = Samanage(args.username, args.password, args.uri)
    results = client.get(args.type, args.count, args.id, args.search)
    if results:
        for result in results:
            print u'{}'.format(result)


if __name__ == '__main__':
    main()
