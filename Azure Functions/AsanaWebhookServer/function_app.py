import hashlib
import hmac
import json
import azure.functions as func
from azure.functions.decorators.core import DataType

import logging
import pyodbc, struct
import os

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)



# conn = pyodbc.connect("Driver={ODBC Driver 18 for SQL Server};Server=tcp:vesperazureserver.database.windows.net,1433;Database=VesperProjectInfoDB;Uid=CloudSA4f70149f;Pwd=Vesper123;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;")
# conn.autocommit(True)
# cursor = conn.cursor()
# conn = """Server=tcp:vesperprojectsserver.database.windows.net,1433;Initial Catalog=VesperProjectInfoDB;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Authentication="Active Directory Default";"""

@app.function_name(name="asanawebhookserver")
@app.route(route="asanatrigger/{ID}")
@app.sql_input(arg_name="inputs",
               command_text="SELECT TOP(1) [ID]                            \
                                                ,[AsanaProjectID]   \
                                                ,[XHookSecret]      \
                                                ,[WebhookID]        \
                            FROM [dbo].[WebhookInfo]",
               command_type="Text",
               parameters="@ID={ID}",
               connection_string_setting="WEBHOOKINFO")#os.environ["VESPERPROJECTINFODB_CONN_STR"])
@app.sql_output(arg_name="outputs",
                command_text="[dbo].[Events]",
                connection_string_setting="WEBHOOKINFO")
def asanatrigger(req: func.HttpRequest, inputs: func.SqlRowList, outputs: func.Out[func.SqlRowList]) -> func.HttpResponse:
    ID = req.route_params.get('ID')
    logging.info(f"Got a request for table ID {ID}")

    # Handshake trigger
    if 'X-Hook-Secret' in req.headers:
        secret = req.headers['X-Hook-Secret']
        logging.info("Python http_trigger received a handshake")
        return func.HttpResponse(status_code=200, headers={'X-Hook-Secret': secret})
    
    # Event/Heartbeat trigger
    if 'X-Hook-Signature' in req.headers:

        # Secret check
        signature = hmac.new(inputs[0]['XHookSecret'].encode('ascii', 'ignore'), msg=req.get_body(), digestmod=hashlib.sha256).hexdigest().encode('ascii', 'ignore')
        if not hmac.compare_digest(signature, req.headers["X-Hook-Signature"].encode('ascii', 'ignore')):
            logging.info("Signature is invalid!")
            return func.HttpResponse("The signature is not valid", status_code=401)
        logging.info("Signature is valid!")

        # Get events
        contents = req.get_json()
        events = list(contents["events"])
        logging.info(f"Received payload of {len(events)} events")
        
        # Empty body heartbeat trigger
        if not events:
            logging.info("Python http_trigger received a heartbeat")
            return func.HttpResponse(status_code=204)
        
        # Event trigger
        logging.info(contents)
        output = func.SqlRowList()
        for event in events:
            output.append(func.SqlRow.from_dict({'Event': str(event), 'AsanaProjectID': str(inputs[0]['AsanaProjectID']), 'WebhookID': str(inputs[0]['WebhookID'])}))
        outputs.set(output)
        logging.info(f"output: {outputs}")
        return func.HttpResponse(status_code=200)
            