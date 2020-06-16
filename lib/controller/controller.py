#!/usr/bin/env python

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from __future__ import division

import os
import re
import time

from lib.controller.action import action
from lib.controller.checks import checkConnection
from lib.controller.checks import checkDynParam
from lib.controller.checks import checkInternet
from lib.controller.checks import checkNullConnection
from lib.controller.checks import checkRegexp
from lib.controller.checks import checkSqlInjection
from lib.controller.checks import checkStability
from lib.controller.checks import checkString
from lib.controller.checks import checkWaf
from lib.controller.checks import heuristicCheckSqlInjection
from lib.core.agent import agent
from lib.core.common import dataToStdout
from lib.core.common import extractRegexResult
from lib.core.common import getFilteredPageContent
from lib.core.common import getPublicTypeMembers
from lib.core.common import getSafeExString
from lib.core.common import hashDBRetrieve
from lib.core.common import hashDBWrite
from lib.core.common import intersect
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import parseTargetUrl
from lib.core.common import popValue
from lib.core.common import pushValue
from lib.core.common import randomInt
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.common import removePostHintPrefix
from lib.core.common import safeCSValue
from lib.core.common import showHttpErrorCodes
from lib.core.common import urldecode
from lib.core.common import urlencode
from lib.core.compat import xrange
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.decorators import stackedmethod
from lib.core.enums import CONTENT_TYPE
from lib.core.enums import HASHDB_KEYS
from lib.core.enums import HEURISTIC_TEST
from lib.core.enums import HTTP_HEADER
from lib.core.enums import HTTPMETHOD
from lib.core.enums import NOTE
from lib.core.enums import PAYLOAD
from lib.core.enums import PLACE
from lib.core.exception import SqlmapBaseException
from lib.core.exception import SqlmapConnectionException
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapNotVulnerableException
from lib.core.exception import SqlmapSilentQuitException
from lib.core.exception import SqlmapSkipTargetException
from lib.core.exception import SqlmapSystemException
from lib.core.exception import SqlmapUserQuitException
from lib.core.exception import SqlmapValueException
from lib.core.settings import ASP_NET_CONTROL_REGEX
from lib.core.settings import CSRF_TOKEN_PARAMETER_INFIXES
from lib.core.settings import DEFAULT_GET_POST_DELIMITER
from lib.core.settings import EMPTY_FORM_FIELDS_REGEX
from lib.core.settings import GOOGLE_ANALYTICS_COOKIE_PREFIX
from lib.core.settings import HOST_ALIASES
from lib.core.settings import IGNORE_PARAMETERS
from lib.core.settings import LOW_TEXT_PERCENT
from lib.core.settings import REFERER_ALIASES
from lib.core.settings import USER_AGENT_ALIASES
from lib.core.target import initTargetEnv
from lib.core.target import setupTargetEnv
from lib.utils.hash import crackHashFile

from thirdparty.six.moves import urllib as _urllib
import xml.etree.ElementTree as XML
import xml.dom.minidom

from lib.core.datatype import AttribDict

def _selectInjection():
    """
    Selection function for injection place, parameters and type.
    """

    points = {}

    for injection in kb.injections:
        place = injection.place
        parameter = injection.parameter
        ptype = injection.ptype

        point = (place, parameter, ptype)

        if point not in points:
            points[point] = injection
        else:
            for key in points[point]:
                if key != 'data':
                    points[point][key] = points[point][key] or injection[key]
            points[point]['data'].update(injection['data'])

    if len(points) == 1:
        kb.injection = kb.injections[0]

    elif len(points) > 1:
        message = "there were multiple injection points, please select "
        message += "the one to use for following injections:\n"

        points = []

        for i in xrange(0, len(kb.injections)):
            place = kb.injections[i].place
            parameter = kb.injections[i].parameter
            ptype = kb.injections[i].ptype
            point = (place, parameter, ptype)

            if point not in points:
                points.append(point)
                ptype = PAYLOAD.PARAMETER[ptype] if isinstance(ptype, int) else ptype

                message += "[%d] place: %s, parameter: " % (i, place)
                message += "%s, type: %s" % (parameter, ptype)

                if i == 0:
                    message += " (default)"

                message += "\n"

        message += "[q] Quit"
        choice = readInput(message, default='0').upper()

        if isDigit(choice) and int(choice) < len(kb.injections) and int(choice) >= 0:
            index = int(choice)
        elif choice == 'Q':
            raise SqlmapUserQuitException
        else:
            errMsg = "invalid choice"
            raise SqlmapValueException(errMsg)

        kb.injection = kb.injections[index]

def _formatInjection(inj):
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else inj.place
    data = "Parameter: %s (%s)\n" % (inj.parameter, paramType)

    for stype, sdata in inj.data.items():
        title = sdata.title
        vector = sdata.vector
        comment = sdata.comment
        payload = agent.adjustLateValues(sdata.payload)
        if inj.place == PLACE.CUSTOM_HEADER:
            payload = payload.split(',', 1)[1]
        if stype == PAYLOAD.TECHNIQUE.UNION:
            count = re.sub(r"(?i)(\(.+\))|(\blimit[^a-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += "    Type: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    Title: %s\n" % title
        data += "    Payload: %s\n" % urldecode(payload, unsafe="&", spaceplus=(inj.place != PLACE.GET and kb.postSpaceToPlus))
        data += "    Vector: %s\n\n" % vector if conf.verbose > 1 else "\n"

    return data

def _showInjections():
    if conf.wizard and kb.wizardMode:
        kb.wizardMode = False

    if kb.testQueryCount > 0:
        header = "sqlmap identified the following injection point(s) with "
        header += "a total of %d HTTP(s) requests" % kb.testQueryCount
    else:
        header = "sqlmap resumed the following injection point(s) from stored session"

    if conf.api:
        conf.dumper.string("", {"url": conf.url, "query": conf.parameters.get(PLACE.GET), "data": conf.parameters.get(PLACE.POST)}, content_type=CONTENT_TYPE.TARGET)
        conf.dumper.string("", kb.injections, content_type=CONTENT_TYPE.TECHNIQUES)
    else:
        data = "".join(set(_formatInjection(_) for _ in kb.injections)).rstrip("\n")
        conf.dumper.string(header, data)

    if conf.tamper:
        warnMsg = "changes made by tampering scripts are not "
        warnMsg += "included in shown payload content(s)"
        logger.warn(warnMsg)

    if conf.hpp:
        warnMsg = "changes made by HTTP parameter pollution are not "
        warnMsg += "included in shown payload content(s)"
        logger.warn(warnMsg)

def _randomFillBlankFields(value):
    retVal = value

    if extractRegexResult(EMPTY_FORM_FIELDS_REGEX, value):
        message = "do you want to fill blank fields with random values? [Y/n] "

        if readInput(message, default='Y', boolean=True):
            for match in re.finditer(EMPTY_FORM_FIELDS_REGEX, retVal):
                item = match.group("result")
                if not any(_ in item for _ in IGNORE_PARAMETERS) and not re.search(ASP_NET_CONTROL_REGEX, item):
                    newValue = randomStr() if not re.search(r"^id|id$", item, re.I) else randomInt()
                    if item[-1] == DEFAULT_GET_POST_DELIMITER:
                        retVal = retVal.replace(item, "%s%s%s" % (item[:-1], newValue, DEFAULT_GET_POST_DELIMITER))
                    else:
                        retVal = retVal.replace(item, "%s%s" % (item, newValue))

    return retVal

def _saveToHashDB():
    injections = hashDBRetrieve(HASHDB_KEYS.KB_INJECTIONS, True)
    if not isListLike(injections):
        injections = []
    injections.extend(_ for _ in kb.injections if _ and _.place is not None and _.parameter is not None)

    _ = dict()
    for injection in injections:
        key = (injection.place, injection.parameter, injection.ptype)
        if key not in _:
            _[key] = injection
        else:
            _[key].data.update(injection.data)
    hashDBWrite(HASHDB_KEYS.KB_INJECTIONS, list(_.values()), True)

    _ = hashDBRetrieve(HASHDB_KEYS.KB_ABS_FILE_PATHS, True)
    hashDBWrite(HASHDB_KEYS.KB_ABS_FILE_PATHS, kb.absFilePaths | (_ if isinstance(_, set) else set()), True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_CHARS):
        hashDBWrite(HASHDB_KEYS.KB_CHARS, kb.chars, True)

    if not hashDBRetrieve(HASHDB_KEYS.KB_DYNAMIC_MARKINGS):
        hashDBWrite(HASHDB_KEYS.KB_DYNAMIC_MARKINGS, kb.dynamicMarkings, True)

def _saveToResultsFile():
    if not conf.resultsFP:
        return

    results = {}
    techniques = dict((_[1], _[0]) for _ in getPublicTypeMembers(PAYLOAD.TECHNIQUE))

    for injection in kb.injections + kb.falsePositives:
        if injection.place is None or injection.parameter is None:
            continue

        key = (injection.place, injection.parameter, ';'.join(injection.notes))
        if key not in results:
            results[key] = []

        results[key].extend(list(injection.data.keys()))

    try:
        for key, value in results.items():
            place, parameter, notes = key
            line = "%s,%s,%s,%s,%s%s" % (safeCSValue(kb.originalUrls.get(conf.url) or conf.url), place, parameter, "".join(techniques[_][0].upper() for _ in sorted(value)), notes, os.linesep)
            conf.resultsFP.write(line)

        conf.resultsFP.flush()
    except IOError as ex:
        errMsg = "unable to write to the results file '%s' ('%s'). " % (conf.resultsFile, getSafeExString(ex))
        raise SqlmapSystemException(errMsg)

def dump(obj):
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))

def _parseQueryParams(queryString):
    result = {}
    for param in queryString.split('&'):
        parts = param.split('=')
        paramName = parts[0]
        paramValue = parts[1] if len(parts) > 1 else None
        result[paramName] = paramValue
    return result

def _parseCookies(cookieString):
    # Takes a cookie string eg "A=1;B=2;..."
    # and returns a corresponding dict. Entries without
    # a value will be returned, but mapped to None.
    result = {}
    for cookie in cookieString.split(';'):
        cookieParts = cookie.split('=', 1)
        name = cookieParts[0]
        value = cookieParts[1] if len(cookieParts) == 2 else None
        result[name] = value
    
    return result

def _collapseHeaderValues(headers):
    # De-duplicate a list of (key, value) header values by discarding earlier values, and
    # for Cookies, merge the contents instead.
    #
    # Need to also consider case-insensitivity of header values; headers
    # are mapped after lower-case transform, and the "cases" version
    # of the header name is just taken from the first occurrence of that header
    # value. (Eg if "Cookie" and "COOKIE" appear, in that order, values are
    # processed under "cookie" but returned under "Cookie" rather than "COOKIE".)
    headerEntries = {}
    headerNames = {}
    for (header, value) in headers:
        lowerHeader = header.lower()
        if lowerHeader not in headerEntries:
            headerEntries[lowerHeader] = value
            headerNames[lowerHeader] = header
        elif not lowerHeader == "cookie":
            headerEntries[lowerHeader] = value
        else:
            # Merge cookie values (where cookie names ARE case-sensitive)
            oldCookies = _parseCookies(headerEntries['cookie'])
            newCookies = _parseCookies(value)

            cookieEntries = []
            keys = set(oldCookies.keys() + newCookies.keys())
            for cookie in keys:
                cookieValue = newCookies.get(cookie) or oldCookies.get(cookie)
                if cookieValue is None:
                    cookieEntries.append(cookie)
                else:
                    cookieEntries.append("%s=%s" % (cookie, cookieValue))
            
            headerEntries['cookie'] = ";".join(cookieEntries)
    
    # Convert from dict back to list[(Key, Value)] while also reapplying
    # original header names
    result = []
    for (header, value) in headerEntries.items():
        originalHeader = headerNames[header]
        result.append((originalHeader, value))

    return result


def _saveToCodeDxReport():
    if not conf.codeDxReport:
        return

    root = XML.Element('report', attrib={'tool': 'sqlmap'})
    findings = XML.SubElement(root, 'findings')

    allHttpMethods = [
        HTTPMETHOD.GET,
        HTTPMETHOD.POST,
        HTTPMETHOD.HEAD,
        HTTPMETHOD.PUT,
        HTTPMETHOD.DELETE,
        HTTPMETHOD.TRACE,
        HTTPMETHOD.OPTIONS,
        HTTPMETHOD.CONNECT,
        HTTPMETHOD.PATCH
    ]

    injectionPlaceToMethod = {
        PLACE.GET: HTTPMETHOD.GET,
        PLACE.POST: HTTPMETHOD.POST,
        PLACE.CUSTOM_POST: HTTPMETHOD.POST
    }

    for entry in kb.accumInjections:
        target = entry.target
        injections = entry.injections

        urlSplit = _urllib.parse.urlsplit(target.url)
        url = "%s://%s%s" % (urlSplit.scheme, urlSplit.netloc, urlSplit.path)
        originalUrlQuery = urlSplit.query

        method = target.method
        headers = target.headers or []

        # Note: See `datatype.py` for `InjectionDict`
        for injection in injections:
            injectedParam = injection.parameter

            for stype, sdata in injection.data.items():

                # Setup for top-level elements of this finding
                finding = XML.SubElement(findings, 'finding', attrib={'severity': 'high'})
                XML.SubElement(finding, 'tool', attrib={
                    'name': 'sqlmap',
                    'category': PAYLOAD.SQLINJECTION[stype],
                    'code': sdata.title
                })

                XML.SubElement(finding, 'cwe', attrib={'id': '89'})

                location = XML.SubElement(finding, 'location', attrib={'type': 'url', 'path': url})
                variants = XML.SubElement(location, 'variants')
                variant = XML.SubElement(variants, 'variant')

                # Resolve request/response data for this specific finding

                # We'll try to insert the payload contents where appropriate (eg
                # query param for GET, request body for POST, etc.) but for PLACE.URI
                # the usage isn't clear at this point. For unhandled cases like this, we'll
                # attach the payload as metadata on the cdx finding so it's at least
                # reported.
                #
                # TODO - Properly test for and handle findings with PLACE.URI
                currentPayload = agent.adjustLateValues(sdata.payload)
                payloadHandled = False

                currentQuery = originalUrlQuery
                if injection.place == PLACE.GET:
                    currentQuery = currentPayload
                    payloadHandled = True

                currentRequestBody = None
                if injection.place in [PLACE.POST, PLACE.CUSTOM_POST]:
                    currentRequestBody = urldecode(currentPayload)
                    payloadHandled = True
                
                # TODO: This may be insufficient (comparing to `paramType` calculated in _formatInjection),
                # should reassess this approach and may need to capture extra information while collecting
                # accumInjections
                currentMethod = method or injectionPlaceToMethod.get(injection.place)
                if currentMethod is None:
                    logger.warn("Unable to infer HTTP method used for injection %s, defaulting to GET" % sdata.title)
                    currentMethod = HTTPMETHOD.GET

                currentHeaders = list(headers)

                if injection.place == PLACE.COOKIE:
                    currentHeaders.append(('Cookie', currentPayload))
                    payloadHandled = True
                elif injection.place == PLACE.CUSTOM_HEADER:
                    currentHeaders.append((injection.parameter, currentPayload))
                    payloadHandled = True
                elif injection.place == PLACE.HOST:
                    currentHeaders.append(('Host', currentPayload))
                    payloadHandled = True
                elif injection.place == PLACE.REFERER:
                    currentHeaders.append(('Referer', currentPayload))
                    payloadHandled = True
                elif injection.place == PLACE.USER_AGENT:
                    currentHeaders.append(('User-Agent', currentPayload))
                    payloadHandled = True

                currentHeaders = _collapseHeaderValues(currentHeaders)

                request = XML.SubElement(variant, 'request', attrib={
                    'method': currentMethod,
                    'path': url, # TODO: Will need to change this for PLACE.URI support
                    'query': currentQuery
                })

                if len(currentHeaders) > 0:
                    requestHeaders = XML.SubElement(request, 'headers')
                    requestHeaders.text = '\n'.join(['%s: %s' % (key, value) for (key, value) in headers])

                if currentRequestBody is not None and injection.place in [PLACE.POST, PLACE.CUSTOM_POST]:
                    requestBody = XML.SubElement(request, 'body', attrib={'truncated': 'false', 'original-length': str(len(currentRequestBody)), 'length': str(len(currentRequestBody))})
                    requestBody.text = currentRequestBody

                # TODO: Is <response> available?
                # (Sort-of - it's stored temporarily and discarded after constructing
                # full injection info)

                # Attach metadata info
                metadata = XML.SubElement(finding, 'metadata')
                XML.SubElement(metadata, 'value', attrib={'key': 'clause'}).text = PAYLOAD.CLAUSE[injection.clause]
                XML.SubElement(metadata, 'value', attrib={'key': 'dbms'}).text = injection.dbms
                XML.SubElement(metadata, 'value', attrib={'key': 'dbms_version'}).text = injection.dbms_version
                XML.SubElement(metadata, 'value', attrib={'key': 'payload_type'}).text = PAYLOAD.PARAMETER[injection.ptype]

                # Vector is generic info on the vuln., as a broader description than just
                # the data payload
                #
                # Storage here is just a copy/paste of what's used in `_formatInjection`,
                # don't have test cases that show `vector` data at this time
                vector = sdata.vector
                if stype == PAYLOAD.TECHNIQUE.UNION:
                    vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
                elif sdata.comment:
                    vector = "%s%s" % (vector, sdata.comment)
                
                # Without proper test cases we can't verify that we're handling all possible
                # values correctly. This provides some sort of fallback for that case
                if vector is not None:
                    if not isinstance(vector, str):
                        logger.warn("vector is not `None` but also isn't a string; converting to string")
                        vector = str(vector)
                        logger.warn("vector converted to: %s" % vector)
                    
                    XML.SubElement(metadata, 'value', attrib={'key': 'vector'}).text = vector

                # TODO: Should figure out when to truncate this
                if not payloadHandled:
                    xmlPayload = XML.SubElement(metadata, 'value', attrib={'key': 'Payload'})
                    xmlPayload.text = currentPayload


    # Pretty-print XML (https://stackoverflow.com/a/60193562)
    xml_string = xml.dom.minidom.parseString(XML.tostring(root)).toprettyxml()
    #xml_string = os.linesep.join([s for s in xml_string.splitlines() if s.strip()]) # remove the weird newline issue
    with open(conf.codeDxReport, "w") as file_out:
        file_out.write(xml_string)

@stackedmethod
def start():
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
    """

    if conf.hashFile:
        crackHashFile(conf.hashFile)

    if conf.direct:
        initTargetEnv()
        setupTargetEnv()
        action()
        return True

    if conf.url and not any((conf.forms, conf.crawlDepth)):
        kb.targets.add((conf.url, conf.method, conf.data, conf.cookie, None))

    if conf.configFile and not kb.targets:
        errMsg = "you did not edit the configuration file properly, set "
        errMsg += "the target URL, list of targets or google dork"
        logger.error(errMsg)
        return False

    if kb.targets and len(kb.targets) > 1:
        infoMsg = "found a total of %d targets" % len(kb.targets)
        logger.info(infoMsg)

    hostCount = 0
    initialHeaders = list(conf.httpHeaders)

    for targetUrl, targetMethod, targetData, targetCookie, targetHeaders in kb.targets:
        try:
            if conf.checkInternet:
                infoMsg = "checking for Internet connection"
                logger.info(infoMsg)

                if not checkInternet():
                    warnMsg = "[%s] [WARNING] no connection detected" % time.strftime("%X")
                    dataToStdout(warnMsg)

                    valid = False
                    for _ in xrange(conf.retries):
                        if checkInternet():
                            valid = True
                            break
                        else:
                            dataToStdout('.')
                            time.sleep(5)

                    if not valid:
                        errMsg = "please check your Internet connection and rerun"
                        raise SqlmapConnectionException(errMsg)
                    else:
                        dataToStdout("\n")

            conf.url = targetUrl
            conf.method = targetMethod.upper().strip() if targetMethod else targetMethod
            conf.data = targetData
            conf.cookie = targetCookie
            conf.httpHeaders = list(initialHeaders)
            conf.httpHeaders.extend(targetHeaders or [])

            if conf.randomAgent or conf.mobile:
                for header, value in initialHeaders:
                    if header.upper() == HTTP_HEADER.USER_AGENT.upper():
                        conf.httpHeaders.append((header, value))
                        break

            conf.httpHeaders = [conf.httpHeaders[i] for i in xrange(len(conf.httpHeaders)) if conf.httpHeaders[i][0].upper() not in (__[0].upper() for __ in conf.httpHeaders[i + 1:])]

            initTargetEnv()
            parseTargetUrl()

            testSqlInj = False

            if PLACE.GET in conf.parameters and not any((conf.data, conf.testParameter)):
                for parameter in re.findall(r"([^=]+)=([^%s]+%s?|\Z)" % (re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER, re.escape(conf.paramDel or "") or DEFAULT_GET_POST_DELIMITER), conf.parameters[PLACE.GET]):
                    paramKey = (conf.hostname, conf.path, PLACE.GET, parameter[0])

                    if paramKey not in kb.testedParams:
                        testSqlInj = True
                        break
            else:
                paramKey = (conf.hostname, conf.path, None, None)
                if paramKey not in kb.testedParams:
                    testSqlInj = True

            if testSqlInj and conf.hostname in kb.vulnHosts:
                if kb.skipVulnHost is None:
                    message = "SQL injection vulnerability has already been detected "
                    message += "against '%s'. Do you want to skip " % conf.hostname
                    message += "further tests involving it? [Y/n]"

                    kb.skipVulnHost = readInput(message, default='Y', boolean=True)

                testSqlInj = not kb.skipVulnHost

            if not testSqlInj:
                infoMsg = "skipping '%s'" % targetUrl
                logger.info(infoMsg)
                continue

            if conf.multipleTargets:
                hostCount += 1

                if conf.forms and conf.method:
                    message = "[#%d] form:\n%s %s" % (hostCount, conf.method, targetUrl)
                else:
                    message = "URL %d:\n%s %s" % (hostCount, HTTPMETHOD.GET, targetUrl)

                if conf.cookie:
                    message += "\nCookie: %s" % conf.cookie

                if conf.data is not None:
                    message += "\n%s data: %s" % ((conf.method if conf.method != HTTPMETHOD.GET else conf.method) or HTTPMETHOD.POST, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "") is None else conf.data)

                if conf.forms and conf.method:
                    if conf.method == HTTPMETHOD.GET and targetUrl.find("?") == -1:
                        continue

                    message += "\ndo you want to test this form? [Y/n/q] "
                    choice = readInput(message, default='Y').upper()

                    if choice == 'N':
                        continue
                    elif choice == 'Q':
                        break
                    else:
                        if conf.method != HTTPMETHOD.GET:
                            message = "Edit %s data [default: %s]%s: " % (conf.method, urlencode(conf.data or "") if re.search(r"\A\s*[<{]", conf.data or "None") is None else conf.data, " (Warning: blank fields detected)" if conf.data and extractRegexResult(EMPTY_FORM_FIELDS_REGEX, conf.data) else "")
                            conf.data = readInput(message, default=conf.data)
                            conf.data = _randomFillBlankFields(conf.data)
                            conf.data = urldecode(conf.data) if conf.data and urlencode(DEFAULT_GET_POST_DELIMITER, None) not in conf.data else conf.data

                        else:
                            if '?' in targetUrl:
                                firstPart, secondPart = targetUrl.split('?', 1)
                                message = "Edit GET data [default: %s]: " % secondPart
                                test = readInput(message, default=secondPart)
                                test = _randomFillBlankFields(test)
                                conf.url = "%s?%s" % (firstPart, test)

                        parseTargetUrl()

                else:
                    if not conf.scope:
                        message += "\ndo you want to test this URL? [Y/n/q]"
                        choice = readInput(message, default='Y').upper()

                        if choice == 'N':
                            dataToStdout(os.linesep)
                            continue
                        elif choice == 'Q':
                            break
                    else:
                        pass

                    infoMsg = "testing URL '%s'" % targetUrl
                    logger.info(infoMsg)

            setupTargetEnv()

            if not checkConnection(suppressOutput=conf.forms) or not checkString() or not checkRegexp():
                continue

            if conf.rParam and kb.originalPage:
                kb.randomPool = dict([_ for _ in kb.randomPool.items() if isinstance(_[1], list)])

                for match in re.finditer(r"(?si)<select[^>]+\bname\s*=\s*[\"']([^\"']+)(.+?)</select>", kb.originalPage):
                    name, _ = match.groups()
                    options = tuple(re.findall(r"<option[^>]+\bvalue\s*=\s*[\"']([^\"']+)", _))
                    if options:
                        kb.randomPool[name] = options

            checkWaf()

            if conf.nullConnection:
                checkNullConnection()

            if (len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None)) and (kb.injection.place is None or kb.injection.parameter is None):

                if not any((conf.string, conf.notString, conf.regexp)) and PAYLOAD.TECHNIQUE.BOOLEAN in conf.technique:
                    # NOTE: this is not needed anymore, leaving only to display
                    # a warning message to the user in case the page is not stable
                    checkStability()

                # Do a little prioritization reorder of a testable parameter list
                parameters = list(conf.parameters.keys())

                # Order of testing list (first to last)
                orderList = (PLACE.CUSTOM_POST, PLACE.CUSTOM_HEADER, PLACE.URI, PLACE.POST, PLACE.GET)

                for place in orderList[::-1]:
                    if place in parameters:
                        parameters.remove(place)
                        parameters.insert(0, place)

                proceed = True
                for place in parameters:
                    # Test User-Agent and Referer headers only if
                    # --level >= 3
                    skip = (place == PLACE.USER_AGENT and (kb.testOnlyCustom or conf.level < 3))
                    skip |= (place == PLACE.REFERER and (kb.testOnlyCustom or conf.level < 3))

                    # --param-filter
                    skip |= (len(conf.paramFilter) > 0 and place.upper() not in conf.paramFilter)

                    # Test Host header only if
                    # --level >= 5
                    skip |= (place == PLACE.HOST and (kb.testOnlyCustom or conf.level < 5))

                    # Test Cookie header only if --level >= 2
                    skip |= (place == PLACE.COOKIE and (kb.testOnlyCustom or conf.level < 2))

                    skip |= (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.COOKIE and intersect(PLACE.COOKIE, conf.skip, True) not in ([], None))
                    skip |= (place == PLACE.HOST and intersect(PLACE.HOST, conf.skip, True) not in ([], None))

                    skip &= not (place == PLACE.USER_AGENT and intersect(USER_AGENT_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.REFERER and intersect(REFERER_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.HOST and intersect(HOST_ALIASES, conf.testParameter, True))
                    skip &= not (place == PLACE.COOKIE and intersect((PLACE.COOKIE,), conf.testParameter, True))

                    if skip:
                        continue

                    if place not in conf.paramDict:
                        continue

                    paramDict = conf.paramDict[place]

                    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else place

                    for parameter, value in paramDict.items():
                        if not proceed:
                            break

                        kb.vainRun = False
                        testSqlInj = True
                        paramKey = (conf.hostname, conf.path, place, parameter)

                        if paramKey in kb.testedParams:
                            testSqlInj = False

                            infoMsg = "skipping previously processed %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif any(_ in conf.testParameter for _ in (parameter, removePostHintPrefix(parameter))):
                            pass

                        elif parameter in conf.rParam:
                            testSqlInj = False

                            infoMsg = "skipping randomizing %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif parameter in conf.skip or kb.postHint and parameter.split(' ')[-1] in conf.skip:
                            testSqlInj = False

                            infoMsg = "skipping %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.paramExclude and (re.search(conf.paramExclude, parameter, re.I) or kb.postHint and re.search(conf.paramExclude, parameter.split(' ')[-1], re.I)):
                            testSqlInj = False

                            infoMsg = "skipping %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif conf.csrfToken and re.search(conf.csrfToken, parameter, re.I):
                            testSqlInj = False

                            infoMsg = "skipping anti-CSRF token parameter '%s'" % parameter
                            logger.info(infoMsg)

                        # Ignore session-like parameters for --level < 4
                        elif conf.level < 4 and (parameter.upper() in IGNORE_PARAMETERS or any(_ in parameter.lower() for _ in CSRF_TOKEN_PARAMETER_INFIXES) or parameter.upper().startswith(GOOGLE_ANALYTICS_COOKIE_PREFIX)):
                            testSqlInj = False

                            infoMsg = "ignoring %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                            logger.info(infoMsg)

                        elif PAYLOAD.TECHNIQUE.BOOLEAN in conf.technique or conf.skipStatic:
                            check = checkDynParam(place, parameter, value)

                            if not check:
                                warnMsg = "%sparameter '%s' does not appear to be dynamic" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.warn(warnMsg)

                                if conf.skipStatic:
                                    infoMsg = "skipping static %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.info(infoMsg)

                                    testSqlInj = False
                            else:
                                infoMsg = "%sparameter '%s' appears to be dynamic" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.info(infoMsg)

                        kb.testedParams.add(paramKey)

                        if testSqlInj:
                            try:
                                if place == PLACE.COOKIE:
                                    pushValue(kb.mergeCookies)
                                    kb.mergeCookies = False

                                check = heuristicCheckSqlInjection(place, parameter)

                                if check != HEURISTIC_TEST.POSITIVE:
                                    if conf.smart or (kb.ignoreCasted and check == HEURISTIC_TEST.CASTED):
                                        infoMsg = "skipping %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                        logger.info(infoMsg)
                                        continue

                                infoMsg = "testing for SQL injection on %sparameter '%s'" % ("%s " % paramType if paramType != parameter else "", parameter)
                                logger.info(infoMsg)

                                injection = checkSqlInjection(place, parameter, value)
                                proceed = not kb.endDetection
                                injectable = False

                                if getattr(injection, "place", None) is not None:
                                    if NOTE.FALSE_POSITIVE_OR_UNEXPLOITABLE in injection.notes:
                                        kb.falsePositives.append(injection)
                                    else:
                                        injectable = True

                                        kb.injections.append(injection)

                                        # In case when user wants to end detection phase (Ctrl+C)
                                        if not proceed:
                                            break

                                        msg = "%sparameter '%s' " % ("%s " % injection.place if injection.place != injection.parameter else "", injection.parameter)
                                        msg += "is vulnerable. Do you want to keep testing the others (if any)? [y/N] "

                                        if not readInput(msg, default='N', boolean=True):
                                            proceed = False
                                            paramKey = (conf.hostname, conf.path, None, None)
                                            kb.testedParams.add(paramKey)

                                if not injectable:
                                    warnMsg = "%sparameter '%s' does not seem to be injectable" % ("%s " % paramType if paramType != parameter else "", parameter)
                                    logger.warn(warnMsg)

                            finally:
                                if place == PLACE.COOKIE:
                                    kb.mergeCookies = popValue()

            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "no parameter(s) found for testing in the provided data "
                    errMsg += "(e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')"
                    if kb.originalPage:
                        advice = []
                        if not conf.forms and re.search(r"<form", kb.originalPage) is not None:
                            advice.append("--forms")
                        if not conf.crawlDepth and re.search(r"href=[\"']/?\w", kb.originalPage) is not None:
                            advice.append("--crawl=2")
                        if advice:
                            errMsg += ". You are advised to rerun with '%s'" % ' '.join(advice)
                    raise SqlmapNoneDataException(errMsg)
                else:
                    errMsg = "all tested parameters do not appear to be injectable."

                    if conf.level < 5 or conf.risk < 3:
                        errMsg += " Try to increase values for '--level'/'--risk' options "
                        errMsg += "if you wish to perform more tests."

                    if isinstance(conf.technique, list) and len(conf.technique) < 5:
                        errMsg += " Rerun without providing the option '--technique'."

                    if not conf.textOnly and kb.originalPage:
                        percent = (100.0 * len(getFilteredPageContent(kb.originalPage)) / len(kb.originalPage))

                        if kb.dynamicMarkings:
                            errMsg += " You can give it a go with the switch '--text-only' "
                            errMsg += "if the target page has a low percentage "
                            errMsg += "of textual content (~%.2f%% of " % percent
                            errMsg += "page content is text)."
                        elif percent < LOW_TEXT_PERCENT and not kb.errorIsNone:
                            errMsg += " Please retry with the switch '--text-only' "
                            errMsg += "(along with --technique=BU) as this case "
                            errMsg += "looks like a perfect candidate "
                            errMsg += "(low textual content along with inability "
                            errMsg += "of comparison engine to detect at least "
                            errMsg += "one dynamic parameter)."

                    if kb.heuristicTest == HEURISTIC_TEST.POSITIVE:
                        errMsg += " As heuristic test turned out positive you are "
                        errMsg += "strongly advised to continue on with the tests."

                    if conf.string:
                        errMsg += " Also, you can try to rerun by providing a "
                        errMsg += "valid value for option '--string' as perhaps the string you "
                        errMsg += "have chosen does not match "
                        errMsg += "exclusively True responses."
                    elif conf.regexp:
                        errMsg += " Also, you can try to rerun by providing a "
                        errMsg += "valid value for option '--regexp' as perhaps the regular "
                        errMsg += "expression that you have chosen "
                        errMsg += "does not match exclusively True responses."

                    if not conf.tamper:
                        errMsg += " If you suspect that there is some kind of protection mechanism "
                        errMsg += "involved (e.g. WAF) maybe you could try to use "
                        errMsg += "option '--tamper' (e.g. '--tamper=space2comment')"

                        if not conf.randomAgent:
                            errMsg += " and/or switch '--random-agent'"

                    raise SqlmapNotVulnerableException(errMsg.rstrip('.'))
            else:
                # Flush the flag
                kb.testMode = False

                _saveToResultsFile()
                _saveToHashDB()
                _showInjections()
                _selectInjection()

            if kb.injection.place is not None and kb.injection.parameter is not None:
                if conf.multipleTargets:
                    message = "do you want to exploit this SQL injection? [Y/n] "
                    condition = readInput(message, default='Y', boolean=True)
                else:
                    condition = True

                if condition:
                    action()
            
            if len(kb.injections) > 0:
                kb.accumInjections.append(AttribDict({
                    'injections': kb.injections,
                    'target': AttribDict({
                        'url': targetUrl,
                        'data': targetData,
                        'method': targetMethod,
                        'cookie': targetCookie,
                        'headers': conf.httpHeaders
                    })
                }))

        except KeyboardInterrupt:
            if conf.multipleTargets:
                warnMsg = "user aborted in multiple target mode"
                logger.warn(warnMsg)

                message = "do you want to skip to the next target in list? [Y/n/q]"
                choice = readInput(message, default='Y').upper()

                if choice == 'N':
                    return False
                elif choice == 'Q':
                    raise SqlmapUserQuitException
            else:
                raise

        except SqlmapSkipTargetException:
            pass

        except SqlmapUserQuitException:
            raise

        except SqlmapSilentQuitException:
            raise

        except SqlmapBaseException as ex:
            errMsg = getSafeExString(ex)

            if conf.multipleTargets:
                _saveToResultsFile()

                errMsg += ", skipping to the next %s" % ("form" if conf.forms else "URL")
                logger.error(errMsg.lstrip(", "))
            else:
                logger.critical(errMsg)
                return False

        finally:
            showHttpErrorCodes()

            if kb.maxConnectionsFlag:
                warnMsg = "it appears that the target "
                warnMsg += "has a maximum connections "
                warnMsg += "constraint"
                logger.warn(warnMsg)

    if kb.dataOutputFlag and not conf.multipleTargets:
        logger.info("fetched data logged to text files under '%s'" % conf.outputPath)

    if conf.multipleTargets:
        if conf.resultsFile:
            infoMsg = "you can find results of scanning in multiple targets "
            infoMsg += "mode inside the CSV file '%s'" % conf.resultsFile
            logger.info(infoMsg)
    
    _saveToCodeDxReport()

    return True
