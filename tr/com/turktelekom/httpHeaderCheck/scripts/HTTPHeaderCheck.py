from multiprocessing import Manager, cpu_count, Queue

from requests.models import Response

from tr.com.turktelekom.httpHeaderCheck.lib.fileRead import readTargetsFromFile
from tr.com.turktelekom.httpHeaderCheck.models.models import HTTPAwareEntity, HTTPHeader

__author__="emre.kisa@turktelekom.com.tr"
from multiprocessing.pool import Pool
import sys
import requests

def listener(file : str, workQueue : Queue):
    try:
        f = open(file, 'w', encoding='utf-8')
        f.write("URL|IS_HTTPS|HTTP_HEADER|RESULT\n")
        while 1:
            m = workQueue.get()
            workQueue.task_done()
            if m == 'kill':
                break
            f.write(str(m) + '\n')
            f.flush()
    except BaseException:
        print(sys.exc_info())
        raise
    finally:
        f.close()

def connectToHTTPAwareEntity(httpAwareEntity:HTTPAwareEntity, retryCount : int = 1, timeout=20, verifySSLCertificate=False) -> Response:
    if(retryCount>=3): #Bir çok kez fail olduysak tekrar deneme
        return
    else:
        httpAwareEntity.failReason = None #Tekrar deniyorsak failReason'ı resetle

    response = None
    try:
        requests.packages.urllib3.disable_warnings() #Bu olmazsa HTTPS Sertifikasını valide edemezse warning veriyor
        user_agent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36'}
        response = requests.get(httpAwareEntity.url.lower(), headers=user_agent, timeout=timeout, verify=verifySSLCertificate) #verify=false SSL sertifikasını verify etme
        if(response.url[:8] == 'https://'):
            httpAwareEntity.isSecureURL = True
        if(response.status_code == 504):
            retryCount += 1
            httpAwareEntity.failReason = HTTPAwareEntity.FailReason.HTTP504_GATEWAY_TIME_OUT
            response = connectToHTTPAwareEntity(httpAwareEntity, retryCount) #tekrar deniyoruz
    except requests.exceptions.Timeout:
        httpAwareEntity.failReason = HTTPAwareEntity.FailReason.CONNECTION_TIMED_OUT
        retryCount += 1
    except BaseException:
        retryCount += 1
        httpAwareEntity.failReason = HTTPAwareEntity.FailReason.CONNECTION_FAILED
        response = connectToHTTPAwareEntity(httpAwareEntity, retryCount) #tekrar deniyoruz
    return response


def worker(workQueue : Queue, httpAwareEntity : HTTPAwareEntity):
    print("Connecting: " + httpAwareEntity.url)
    response = connectToHTTPAwareEntity(httpAwareEntity)
    if(response == None):
        if(httpAwareEntity.failReason == HTTPAwareEntity.FailReason.CONNECTION_TIMED_OUT):
            formData = httpAwareEntity.url + "|-|OK|Connection timed out."
            print("Connection timed out: " + httpAwareEntity.url)
        else:
            formData = httpAwareEntity.url + "|-|ERROR|Connection failed. Tried 3 times"
            print("Connection failed: " + httpAwareEntity.url)
        workQueue.put(formData)
        return
    elif(response.is_redirect or response.is_permanent_redirect):
        formData = httpAwareEntity.url + "|" + str(httpAwareEntity.isSecureURL) + "|MANUEL_CHECK|REDIRECTED" #Redirect var
        workQueue.put(formData)
    elif(response.status_code>=100 and response.status_code<300):
        parseHeadersFromResponse(httpAwareEntity, response)
        if(httpAwareEntity.securityHeaders != None and len(httpAwareEntity.securityHeaders)>0):
            for securityHeader in httpAwareEntity.securityHeaders:
                if(securityHeader.name == 'set-cookie'):
                    if('httponly'  in securityHeader.value.lower()):
                        formData = httpAwareEntity.url + "|" + str(httpAwareEntity.isSecureURL) + "|" + str(securityHeader).replace("|","-")  + "|" + "HTTPOnly"
                        workQueue.put(formData)
                    if('secure' in securityHeader.value.lower()):
                        formData = httpAwareEntity.url + "|" + str(httpAwareEntity.isSecureURL) + "|" + str(securityHeader).replace("|","-")  + "|" + "Secure"
                        workQueue.put(formData)
                    if(not ('httponly' in securityHeader.value.lower() or 'secure' in securityHeader.value.lower())):
                        formData = httpAwareEntity.url + "|" + str(httpAwareEntity.isSecureURL) + "|" + str(securityHeader).replace("|","-")
                        workQueue.put(formData)
                else:
                    formData = httpAwareEntity.url + "|" + str(httpAwareEntity.isSecureURL) + "|" + str(securityHeader).replace("|","-")
                    workQueue.put(formData)
        else:
            formData = httpAwareEntity.url + "|" + str(httpAwareEntity.isSecureURL) + "|" + "NO_SECURITY|No security related headers found"
            workQueue.put(formData)
    else:
        formData = httpAwareEntity.url + "|-| ERROR |HTTP Kodu : " + str(response.status_code)
        workQueue.put(formData)

    print("Done: " + httpAwareEntity.url)

def parseHeadersFromResponse(httpAwareEntity:HTTPAwareEntity, response) -> [HTTPHeader]:
    headersToCheck = ['content-security-policy',
                        'x-xss-protection',
                        'x-frame-options',
                        'strict-transport-security',
                        'set-cookie',
                        'x-content-type-options',
                        'x-download-options',
                        'x-permitted-cross-domain-policies',
                        'public-key-pins', 'public-key-pins-report-only']

    for headerToCheck in headersToCheck:
        try:
            if(response.headers[headerToCheck] != None):
                http_header = HTTPHeader(headerToCheck, response.headers[headerToCheck])
                httpAwareEntity.securityHeaders.append(http_header)
        except KeyError:
            pass

def main(args):
    targets = readTargetsFromFile(args)
    httpAwareEntities = []
    for target in targets:
        httpAwareEntities.append(HTTPAwareEntity(target))

    print(str(len(httpAwareEntities)) + " IP adresses will be checked")
    print("Input file location : " + args.inputFileLocation[0])
    print("Output file location : " + args.outputFileLocation[0])

    with Pool(cpu_count() * 1) as pool:
        manager = Manager()
        workerQueue = manager.JoinableQueue()
        pool.apply_async(listener, (args.outputFileLocation[0], workerQueue)) #dosyaya aynı anda sadece 1 process yazması lazım, bu yüzden önce dosyaya yazacak processi açıp workerQueue'ya atıyorum

        try:
            #worker'lar çalışmaya başlıyor
            jobs = []
            for httpAwareEntity in httpAwareEntities:
                job = pool.apply_async(worker, (workerQueue, httpAwareEntity))
                jobs.append(job)

            # pool'daki workerlardan sonucları alıyorum
            for job in jobs:
                job.get()
        except Exception as e:
            print("EXCEPTION OCCURED! " + str(e))
        #finally:
            #işimiz bitince workerQueue'ya kill komutu gönderiyorum
        workerQueue.put('kill')
        #workerQueue.join()
    pool.close()
    pool.join()
    print("Completed successfully")