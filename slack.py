import json
import logging
import traceback
import time
import os

import requests
from urllib.request import urlopen, Request
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

PATH = os.path.dirname(os.path.abspath(__file__))
slack_config_path = os.path.join(PATH, "etc", "slack.json")
if os.path.exists(slack_config_path):
    with open(slack_config_path, "rb") as f:
        slack_config = json.load(f)
else:
    slack_config = None
    logger.warning("Slack not configured")

class Slack:
    def __init__(self):
        if not slack_config:
            return
        self.url = slack_config["url"]
        self.bot_token = slack_config["bot_token"]
        self.channel = slack_config.get("channel")

    def UrlPOST(self, url, params):
        params["token"] = self.bot_token
        p = urlencode(params)
        p = p.encode("ascii")  # data should be bytes
        req = Request(url, p)
        result = None
        try:
            response = urlopen(req, timeout=60)
            result = response.read()
            #print(result)
        except Exception:
            logger.error("Error in POST %s" % traceback.format_exc())
        return result

    def BotPOST(self, url, params):
        params["token"] = self.bot_token
        p = urlencode(params)
        p = p.encode("ascii")  # data should be bytes
        req = Request(url, p)
        result = None
        try:
            response = urlopen(req, timeout=60)
            result = response.read()
            print(result)
            result = json.loads(result)
        except Exception:
            logger.error("Error in POST %s" % traceback.format_exc())
        return result
        
    def POST(self, url, params):
        result = None
        print(params)
        data = json.dumps(params)
        data = data.encode("ascii")  # data should be bytes
        req = Request(url, data)
        # req.add_header('Content-Type', 'application/json')
        req.add_header("Authorization", "Bearer " + self.bot_token)
        try:
            response = urlopen(req, timeout=60)
            result = json.loads(response.read())
        except Exception:
            logger.warning("POST failed to %s - %s" % (url, traceback.format_exc()))

        if result is None:
            logger.error("POST failed to %s" % url)

        return result

    def GET(self, params=None):
        url = self.url
        if params:
            req = Request("%s?%s" % (url, urlencode(params)))
        else:
            req = Request(url)
        response = urlopen(req, timeout=60)
        result = json.loads(response.read())
        return result

    def GenerateToken(self):
        url = "	https://slack.com/api/oauth.v2.access"
        params = {}
        params["client_id"] = ""
        params["client_secret"] = ""
        params["code"] = ""
        return self.UrlPOST(url, params)

    def OldPostFile(self, channel_id, message, content):
        # this api is deprecated
        url = "https://slack.com/api/files.upload"
        params = {}
        params["channels"] = channel_id
        params["content"] = content
        params["filetype"] = "text"
        params["title"] = message
        return self.BotPOST(url, params)

    def PostFile(self, channel_id, filename, message, content):
        url = "https://slack.com/api/files.getUploadURLExternal"
        params = {}
        params["filename"] = filename
        params["length"] = len(content)
        resp = self.BotPOST(url, params)
        if not resp:
            return
        resp = json.loads(resp)
        if not resp.get("ok"):
            logger.warning("Error in getUploadURLExternal")
            return
        upload_url = resp.get("upload_url")
        file_id = resp.get("file_id")
        with open(filename, "w", encoding="utf8") as f:
            f.write(content)
        with open(filename, "r", encoding="utf8") as f:
            try:
                requests.post(
                    upload_url, files={filename: f}, params={"token": self.bot_token}
                )
            except Exception:
                logger.warning("Upload file failed: %s" % (traceback.format_exc()))
        try:
            os.remove(filename)
        except Exception:
            logger.warning("Error removing file?")
        url = "https://slack.com/api/files.completeUploadExternal"
        params = {}
        params["files"] = [{"id":file_id, "title":message}]
        params["channel_id"] = channel_id
        return self.BotPOST(url, params)
        
    def SendMessage(self, channel_id, message, markdown_text=None, thread_ts=None, blocks=None):
        url = "https://slack.com/api/chat.postMessage"
        params = {}
        params["channel"] = channel_id
        if message:
            params["text"] = message
        if markdown_text:
            params["markdown_text"] = markdown_text
        if thread_ts:
            params["thread_ts"] = thread_ts
        if blocks:
            params["blocks"] = blocks
        print(params)
        time.sleep(0.1)
        return self.BotPOST(url, params)

    def GetMessage(self, channel_id, oldest=None, newest=None, limit=None):
        url = "https://slack.com/api/conversations.history"
        params = {}
        params["channel"] = channel_id
        if oldest:
            params["oldest"] = oldest
        if newest:
            params["newest"] = newest
        if limit:
            params["limit"] = limit
        else:
            params["limit"] = 10
        params["inclusive"] = False
        return self.UrlPOST(url, params)

    def GetConversation(self, channel_id, ts, limit=None):
        url = "https://slack.com/api/conversations.replies"
        params = {}
        params["channel"] = channel_id
        params["ts"] = ts
        if limit:
            params["limit"] = limit
        else:
            params["limit"] = 10
        params["inclusive"] = False
        return self.UrlPOST(url, params)
  
def root_logger(level, file_name=None):
    logger = logging.getLogger("detonate")
    logger.setLevel(level)
    ch = logging.StreamHandler()
    ch.setLevel(level)
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s:%(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if file_name:
        # create file handler
        fh = logging.FileHandler(file_name)
        fh.setLevel(logging.INFO)
        # create formatter
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s:%(message)s')
        # add formatter to fh
        fh.setFormatter(formatter)
        # add fh to logger
        logger.addHandler(fh)
