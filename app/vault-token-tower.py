import argparse
import hvac
import urllib3
from flask import Flask
from flask_restful import Resource, Api
from flask_jsonpify import jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# # generic error handling
# def log_exception(sender, exception, **extra):
#     print("Got an exception from {} during processing: {}".format(sender, exception))
#
#
# errors = {
#     'VaultIsSealed': {
#         'message': "The Vault is sealed.",
#         'status': 500
#     }
# }

app = Flask(__name__)
parser = argparse.ArgumentParser(description='Vault Token Tower')
parser.add_argument('--vault-host', required=False, default='vault', help='Vault Hostname')
parser.add_argument('--vault-port', required=False, default=8200, help='Vault Port')
parser.add_argument('--vault-ssl', action='store_true', help='Vault SSL')
parser.add_argument('--debug', action='store_true', help='Debug')
args = vars(parser.parse_args())

connection_scheme = 'http'
if args['vault_ssl']:
    connection_scheme = 'https'
vault_uri = '{}://{}:{}'.format(connection_scheme, args['vault_host'], args['vault_port'])
# got_request_exception.connect(log_exception, app)
# api = Api(app, errors=errors)
api = Api(app)
vc = hvac.Client(url=vault_uri, token=open('token', 'r').read().strip(), verify=False)
assert vc.is_authenticated()

class get_token(Resource):
    """
    Test class to see what the token value looks like
    """
    def get(self):
        if not vc.is_sealed():
            result = {'token': vc.lookup_token()}
            return jsonify(result)
        else:
            print("Vault is sealed. Cannot perform request.")
            return jsonify({'vault_status': 'Vault is sealed'})


class get_roleid(Resource):
    """
    equivalent of `vault read auth/approle/role/<your_role>/role-id
    """
    def get(self, role_name):
        if not vc.is_sealed():
            role_info = vc.read("auth/approle/role/{}/role-id".format(role_name))
            return jsonify(role_id=role_info['data']['role_id'])
        else:
            print("Vault is sealed. Cannot perform request.")
            return jsonify({'vault_status': 'Vault is sealed'})


class get_wrap_token(Resource):
    """
    Equivalent of `vault write -wrap-ttl=60s -f auth/approle/role/<your_role>/secret-id`
    """
    def post(self, role_name):
        if not vc.is_sealed():
            #TODO flexible ttl
            secret_info = vc.write("auth/approle/role/{}/secret-id".format(role_name), wrap_ttl='60s')
            return jsonify(wrap_token=secret_info['wrap_info']['token'])
        else:
            print("Vault is sealed. Cannot perform request.")
            return jsonify({'vault_status': 'Vault is sealed'})


def get_vault_status():
    print("Vault status:")
    print("* Vault is initialized? {}".format(vc.is_initialized()))
    print("* Vault is sealed? {}".format(vc.is_sealed()))

    # while vc.is_sealed():
    #     print("Vault is currently sealed. Checking again in 10s.")
    #     time.sleep(10)


# print vault status
get_vault_status()

# build endpoints
api.add_resource(get_token, '/token')
api.add_resource(get_roleid, '/roleid/<role_name>')
api.add_resource(get_wrap_token, '/wraptoken/<role_name>')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=args['debug'])
