"""utils function"""


def formatResponse(msg, status, data, statuscode):
    """method to create resspose dict"""
    return {
        'status': status,
        'message': msg.capitalize(),
        'code': statuscode,
        'data': data
    }
