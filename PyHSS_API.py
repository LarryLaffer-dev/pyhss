import sys
import json
from flask import Flask, request, jsonify, Response
from flask_restx import Api, Resource, fields, reqparse, abort
from werkzeug.middleware.proxy_fix import ProxyFix
app = Flask(__name__)

import database_new2
APN = database_new2.APN
Serving_APN = database_new2.Serving_APN
AUC = database_new2.AUC
SUBSCRIBER = database_new2.SUBSCRIBER
IMS_SUBSCRIBER = database_new2.IMS_SUBSCRIBER


app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app, version='1.0', title='PyHSS OAM API',
    description='Restful API for working with PyHSS',
    doc='/docs/'
)

ns_apn = api.namespace('apn', description='PyHSS APN Functions')
ns_auc = api.namespace('auc', description='PyHSS AUC Functions')
ns_subscriber = api.namespace('subscriber', description='PyHSS SUBSCRIBER Functions')
ns_ims_subscriber = api.namespace('ims_subscriber', description='PyHSS IMS SUBSCRIBER Functions')

parser = reqparse.RequestParser()
parser.add_argument('APN JSON', type=str, help='APN Body')

APN_model = api.schema_model('APN JSON', 
    database_new2.Generate_JSON_Model_for_Flask(APN)
)
Serving_APN_model = api.schema_model('Serving APN JSON', 
    database_new2.Generate_JSON_Model_for_Flask(Serving_APN)
)
AUC_model = api.schema_model('AUC JSON', 
    database_new2.Generate_JSON_Model_for_Flask(AUC)
)
SUBSCRIBER_model = api.schema_model('SUBSCRIBER JSON', 
    database_new2.Generate_JSON_Model_for_Flask(SUBSCRIBER)
)
IMS_SUBSCRIBER_model = api.schema_model('IMS_SUBSCRIBER JSON', 
    database_new2.Generate_JSON_Model_for_Flask(IMS_SUBSCRIBER)
)


@ns_apn.route('/<string:apn_id>')
class PyHSS_APN_Get(Resource):
    def get(self, apn_id):
        '''Get all APN data for specified APN ID'''
        try:
            apn_data = database_new2.GetObj(APN, apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "APN ID not found " + str(apn_id)}
            return jsonify(response_json), 404

    def delete(self, apn_id):
        '''Delete all APN data for specified APN ID'''
        try:
            apn_data = database_new2.DeleteObj(APN, apn_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "APN ID not found " + str(apn_id)}
            return jsonify(response_json), 404

    @ns_apn.doc('Update APN Object')
    @ns_apn.expect(APN_model)
    def patch(self, apn_id):
        '''Update APN data for specified APN ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            apn_data = database_new2.UpdateObj(APN, json_data, apn_id)
            print("Updated object")
            print(apn_data)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to update"}
            return jsonify(response_json), 404    

@ns_apn.route('/')
class PyHSS_APN(Resource):
    @ns_apn.doc('Create APN Object')
    @ns_apn.expect(APN_model)
    def put(self):
        '''Create new APN'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            apn_id = database_new2.CreateObj(APN, json_data)
            return apn_id, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to create APN"}
            return jsonify(response_json), 404

@ns_auc.route('/<string:auc_id>')
class PyHSS_AUC_Get(Resource):
    def get(self, auc_id):
        '''Get all AuC data for specified AuC ID'''
        try:
            apn_data = database_new2.GetObj(AUC, auc_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "auc_id ID not found " + str(auc_id)}
            return jsonify(response_json), 404

    def delete(self, auc_id):
        '''Delete all AUC data for specified AUC ID'''
        try:
            data = database_new2.DeleteObj(AUC, auc_id)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "AUC ID not found " + str(auc_id)}
            return jsonify(response_json), 404

    @ns_auc.doc('Update AUC Object')
    @ns_auc.expect(AUC_model)
    def patch(self, auc_id):
        '''Update AuC data for specified AuC ID'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database_new2.UpdateObj(AUC, json_data, auc_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to update"}
            return jsonify(response_json), 404

@ns_auc.route('/')
class PyHSS_AUC(Resource):
    @ns_auc.doc('Create AUC Object')
    @ns_auc.expect(AUC_model)
    def put(self):
        '''Create new AUC'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database_new2.CreateObj(AUC, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to create AUC"}
            return jsonify(response_json), 404

@ns_subscriber.route('/<string:subscriber_id>')
class PyHSS_SUBSCRIBER_Get(Resource):
    def get(self, subscriber_id):
        '''Get all SUBSCRIBER data for specified subscriber_id'''
        try:
            apn_data = database_new2.GetObj(SUBSCRIBER, subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "subscriber_id ID not found " + str(subscriber_id)}
            return jsonify(response_json), 404

    def delete(self, subscriber_id):
        '''Delete all data for specified subscriber_id'''
        try:
            data = database_new2.DeleteObj(SUBSCRIBER, subscriber_id)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "subscriber_id not found " + str(subscriber_id)}
            return jsonify(response_json), 404

    @ns_subscriber.doc('Update SUBSCRIBER Object')
    @ns_subscriber.expect(SUBSCRIBER_model)
    def patch(self, subscriber_id):
        '''Update SUBSCRIBER data for specified subscriber_id'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database_new2.UpdateObj(SUBSCRIBER, json_data, subscriber_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to update"}
            return jsonify(response_json), 404

@ns_subscriber.route('/')
class PyHSS_SUBSCRIBER(Resource):
    @ns_subscriber.doc('Create SUBSCRIBER Object')
    @ns_subscriber.expect(SUBSCRIBER_model)
    def put(self):
        '''Create new SUBSCRIBER'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database_new2.CreateObj(SUBSCRIBER, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to create SUBSCRIBER"}
            return jsonify(response_json), 404

@ns_ims_subscriber.route('/<string:ims_subscriber_id>')
class PyHSS_IMS_SUBSCRIBER_Get(Resource):
    def get(self, ims_subscriber_id):
        '''Get all SUBSCRIBER data for specified ims_subscriber_id'''
        try:
            apn_data = database_new2.GetObj(IMS_SUBSCRIBER, ims_subscriber_id)
            return apn_data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "ims_subscriber_id ID not found " + str(ims_subscriber_id)}
            return jsonify(response_json), 404

    def delete(self, ims_subscriber_id):
        '''Delete all data for specified ims_subscriber_id'''
        try:
            data = database_new2.DeleteObj(IMS_SUBSCRIBER, ims_subscriber_id)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "ims_subscriber_id not found " + str(ims_subscriber_id)}
            return jsonify(response_json), 404

    @ns_ims_subscriber.doc('Update IMS SUBSCRIBER Object')
    @ns_ims_subscriber.expect(IMS_SUBSCRIBER_model)
    def patch(self, ims_subscriber_id):
        '''Update IMS SUBSCRIBER data for specified ims_subscriber'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database_new2.UpdateObj(IMS_SUBSCRIBER, json_data, ims_subscriber_id)
            print("Updated object")
            print(data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to update"}
            return jsonify(response_json), 404

@ns_ims_subscriber.route('/')
class PyHSS_IMS_SUBSCRIBER(Resource):
    @ns_ims_subscriber.doc('Create IMS SUBSCRIBER Object')
    @ns_ims_subscriber.expect(IMS_SUBSCRIBER_model)
    def put(self):
        '''Create new IMS SUBSCRIBER'''
        try:
            json_data = request.get_json(force=True)
            print("JSON Data sent: " + str(json_data))
            data = database_new2.CreateObj(IMS_SUBSCRIBER, json_data)
            return data, 200
        except Exception as E:
            print(E)
            response_json = {'result': 'Failed', 'Reason' : "Failed to create IMS_SUBSCRIBER"}
            return jsonify(response_json), 404


if __name__ == '__main__':
    app.run(debug=True)
