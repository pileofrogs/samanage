#!/usr/bin/env python

import sys
import json
import urllib
import logging
import argparse
import requests
import inspect
from pprint import pprint

# todo
#  get list of departments
#  get list of hardware categories

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

class CatalogItems(Record):
    pass

class Department(Record):
    pass

class Incident(Record):
    def __init__(self, json_payload):
        super(Incident, self).__init__(json_payload)
        self.subcategory         = json_payload.get('subcategory', '')
        self.updated_at          = json_payload.get('updated_at', '')
        #This is a massive object, shuld parse it a bit better
        #self.assignee           = json_payload.get('assignee', '')
        self.href                = json_payload.get('href', '')
        self.created_by          = json_payload.get('created_by', '')
        self.created_at          = json_payload.get('created_at', '')
        self.priority            = json_payload.get('priority', '')
        self.state               = json_payload.get('state', '')
        self.description         = json_payload.get('description', '')
        self.description_no_html = json_payload.get('description_no_html', '')
        self.requester           = json_payload.get('requester', '')

#class User(Record):
#    def __init__(self, json_payload):
#        super(User, self).__init__(json_payload)
#        self.title      = json_payload.get('title', '')
#        self.department = json_payload.get('department', '')
#        self.email      = json_payload.get('email', '')

class Hardware(Record):
    def __init__(self, json_payload):
        super(Hardware, self).__init__(json_payload)
        self.bio               = [{'ssn': ''}]
        self.address           = json_payload.get('address', '')
        self.asset_tag         = json_payload.get('asset_tag', '')
        self.category          = json_payload.get('category', '')
        self.department        = json_payload.get('department', '')
        self.description       = json_payload.get('description', '')
        self.domain            = json_payload.get('domain', '')
        self.ip                = json_payload.get('ip', '')
        self.latitude          = json_payload.get('latitude', '')
        self.longitude         = json_payload.get('longitude', '')
        self.networks          = json_payload.get('networks', '')
        self.notes             = json_payload.get('notes', '')
        self.owner             = json_payload.get('owner', '')
        self.status            = json_payload.get('status', '')
        self.technical_contact = json_payload.get('technical_contact', '')
        self.username          = json_payload.get('username', '')

    def get_incidents(self, client):
        '''get a list of incidents using the client passed'''
        uri = '{}/hardwares/{}-{}/incidents.json'.format(
                client.uri, self.id, self.name.replace('.','-'))
        return client._get_raw(uri, 'incidents')

def record_factory ( obj_name, init_args={} ):
    def init ( self, payload ):
        init_args.update(payload)
        for key, value in init_args.items():
            setattr(self,key,value)

    return type( obj_name, (Record,),{ '__init__': init} )


class Samanage(object):

    supported_types = {
            'hardwares': record_factory('Hardware'),
            'users': record_factory('User'),
            'departments': Department,
            'catalog_items': CatalogItems,
            'incidents': Incident,
            'categories' : record_factory('Categories',{'onefish': 'twofish'})
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
            raise ValueError('{} not supported'.format(record_type))
        if record_id:
            return '{}/{}/{}.json'.format(self.uri, record_type, record_id) 
        return '{}/{}.json'.format(self.uri, record_type) 

    #def _get_uri(self, record_type, pagesize=100, record_id=None, search={}):
    #    '''build the uri with correct parameters'''
    #    uri = self._uri(record_type, record_id)
    #    search['per_page'] = pagesize
    #    if search:
    #        uri += '?{}'.format(urllib.urlencode(search))
    #        self.logger.debug('add search paramter: {}'.format(uri))
    #    return uri


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
