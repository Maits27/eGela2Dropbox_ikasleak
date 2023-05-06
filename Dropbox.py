import requests
import urllib
import webbrowser
from socket import AF_INET, socket, SOCK_STREAM
import json
import helper

app_key = ''
app_secret = ''
server_addr = "localhost"
server_port = 8090
redirect_uri = "http://" + server_addr + ":" + str(server_port)

class Dropbox:
    _access_token = ""
    _path = "/"
    _files = []
    _root = None
    _msg_listbox = None

    def __init__(self, root):
        self._root = root

    def local_server(self):
        print("\n\tStep 4: Handle the OAuth 2.0 server response")
        # https://developers.google.com/identity/protocols/oauth2/native-app#handlingresponse
        # 8090. portuan dagoen zerbitzaria sartu
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 8090))
        server_socket.listen(1)
        print("\t\tSocket listening on port 8090")

        print("\t\tWaiting for client requests...")
        # ondorengo lerroan programa gelditzen da zerbitzariak 302 eskaera jasotzen duen arte
        client_connection, client_address = server_socket.accept()

        # nabitzailetik 302 eskaera jaso
        eskaera = client_connection.recv(1024).decode()
        print("\t\tNabigatzailetik ondorengo eskaera jaso da:")
        print("\n" + eskaera)
        # eskaeran "auth_code"-a bilatu
        # TODO OAUTH TOKEN ERABILTZEN DU ACCESS TOKEN BAT LORTZEKO ERABILTZEN DA
        lehenengo_lerroa = eskaera.split('\n')[0]
        aux_auth_code = lehenengo_lerroa.split(' ')[1]
        auth_code = aux_auth_code[7:].split('&')[0]
        print("auth_code: " + auth_code)

        ############################################################################################
        # erabiltzaileari erantzun bat bueltatu
        http_response = """\
            HTTP/1.1 200 OK

            <html>
            <head><title>Proba</title></head>
            <body>
            The authentication flow has completed. Close this window.
            </body>
            </html>
            """

        client_connection.sendall(str.encode(http_response))
        client_connection.close()
        server_socket.close()

        ############################################################################################

        return auth_code

    def do_oauth(self):
        print("\nObtaining OAuth  access tokens")
        # Authorization
        print("\tStep 2: Send a request to Google's OAuth 2.0 server")
        base_uri = 'https://www.dropbox.com/oauth2/authorize'
        goiburuak = {'Host': 'www.dropbox.com'}
        datuak = {'response_type': 'code',
                  'client_id': app_key,
                  'redirect_uri': 'http://127.0.0.1:8090',
                  'scope': 'files.content.read'}
        datuak_kodifikatuta = urllib.parse.urlencode(datuak)
        step2_uri = base_uri + '?' + datuak_kodifikatuta
        print("\t" + step2_uri)
        webbrowser.open_new(step2_uri)

        ###############################################################################################################

        print("\n\tStep 3: DropBox prompts user for consent")

        auth_code = local_server()

        ###############################################################################################################
        # Exchange authorization code for access token
        print("\n\tStep 5: Exchange authorization code for refresh and access tokens")

        uri = 'https://api.dropboxapi.com/oauth2/token'
        goiburuak = {'Host': 'oauth2.googleapis.com',
                     'Content-Type': 'application/x-www-form-urlencoded'}
        datuak = {'code': auth_code,
                  'grant_type': 'authorization_code',
                  'redirect_uri': 'http://127.0.0.1:8090',
                  'client_id': app_key,
                  'client_secret': app_secret}
        datuak_kodifikatuta = urllib.parse.urlencode(datuak)
        goiburuak['Content-Length'] = str(len(datuak_kodifikatuta))
        erantzuna = requests.post(uri, data=datuak, allow_redirects=False)
        status = erantzuna.status_code
        print(status)
        # Google responds to this request by returning a JSON object
        # that contains a short-lived access token and a refresh token.

        edukia = erantzuna.content
        print("\nEdukia\n")
        print(edukia)
        edukia_json = json.loads(edukia)
        access_token = edukia_json['access_token']
        print("\nAccess token: " + access_token)

        self._access_token = access_token
        self._root.destroy()

    def list_folder(self, msg_listbox, cursor="", edukia_json_entries=[]):
        if not cursor:
            print("/list_folder")
            uri = 'https://api.dropboxapi.com/2/files/list_folder'
            datuak = {'path': '', 'recursive': True}
            # sartu kodea hemen
        else:
            print("/list_folder/continue")
            uri = 'https://api.dropboxapi.com/2/files/list_folder/continue'
            datuak = {'cursor': cursor}
            # sartu kodea hemen

        # Call Dropbox API
        goiburuak = {'Host': 'api.dropboxapi.com', 'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'}
        # TODO en la eskaera hay que mandar un JSON asi que hay que pasar los datos de hiztegi de python a JSON
        datuak_json = json.dumps(datuak)
        erantzuna = requests.post(uri, headers=goiburuak, data=datuak_json, allow_redirects=False)
        print(erantzuna.status_code)
        print("\nErantzuna\n")
        edukia = erantzuna.content
        print(edukia)

        edukia_json = json.loads(edukia)
        if edukia_json['has_more']:
            # sartu kodea hemen
            self.list_folder(msg_listbox, edukia_json['cursor'], edukia_json_entries)
        else:
            # sartu kodea hemen
            self._files = helper.update_listbox2(msg_listbox, self._path, edukia_json_entries)

    def transfer_file(self, file_path, file_data):
        print("/upload " + file_path)
        # sartu kodea hemen

    def delete_file(self, file_path):
        print("/delete_file " + file_path)
        # sartu kodea hemen

    def create_folder(self, path):
        print("/create_folder " + path)
        # sartu kodea hemen
