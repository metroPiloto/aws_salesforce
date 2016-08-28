public class aws_connectivity {
    private String hashAlgorithmName = 'AWS4-HMAC-SHA256';
    
    private String getAccessKeyID(String awsConfigNameOrSecretKey) {
        String accessKey;
            List<charterforce__AWS_Config__c> aws = [SELECT charterforce__accessKey__c,
                charterforce__secretKey__c,
                charterforce__host__c,
                charterforce__queue__c
                FROM charterforce__AWS_Config__c
                WHERE name = :awsConfigNameOrSecretKey LIMIT 1];
            
            if (aws.size() > 0) {
                accessKey = aws[0].charterforce__accessKey__c;        
            } else {
                accessKey = '';
            }
            return accessKey; 
    }

    public String createSignedAWSRequest(String awsConfigNameOrSecretKey, String method, String canonicalURI, String host, String service, String region, String payload, Map<String,String> headers, Map<String,String> params, String dateString) {
        if (canonicalURI != '/') {
            canonicalURI = '/' + encode(canonicalURI.removeStart('/'));
        }
        
        String accessKeyID = getAccessKeyID(awsConfigNameOrSecretKey);
        List<String> sortedHeaders = new List<String>();
        sortedHeaders.addAll(headers.keySet());
        sortedHeaders.sort();
        String headerStr = '';
        String signedHeaderStr = '';
        for (String key : sortedHeaders) {
            String value = headers.get(key);
            headerStr += key + ':' + value + '\n';
            signedHeaderStr += key + ';';
        }
        signedHeaderStr = signedHeaderStr.removeEnd(';') + '\n';
        String hashedPayload = getSHA256HexDigest(payload);
        
        List<String> sortedKeys = new List<String>();
        sortedKeys.addAll(params.keySet());
        sortedKeys.sort();
        
        String canonicalRequest = method + '\n' + canonicalURI + '\n';
        Integer p = 0;
        for (String key : sortedKeys) {
            String value = params.get(key);
            if (p > 0) {
                canonicalRequest += '&';
            }
            p++;
            canonicalRequest += key+'='+encode(value);
        }
        canonicalRequest += '\n' + headerStr + '\n';
        canonicalRequest += signedHeaderStr;
        canonicalRequest += hashedPayload;

        String hashedCanonicalRequest = getSHA256HexDigest(canonicalRequest);
                
        String credentialScope = dateString.left(8) + '/' + region + '/' + service + '/' + 'aws4_request';
        String stringToSign = hashAlgorithmName + '\n' + dateString + '\n' + credentialScope + '\n' + hashedCanonicalRequest;
        
        String signature = deriveSigningKey(awsConfigNameOrSecretKey, dateString.left(8), region, service, stringToSign);
        
        //Create Authorization Header
        String authorizationHeader = 'Authorization: ' + hashAlgorithmName + ' Credential=' + getAccessKeyID(awsConfigNameOrSecretKey) + '/' + credentialScope + ', SignedHeaders=' + signedHeaderStr + ', Signature=' + signature;
        
        return authorizationHeader;
    }

    public String createSignedAWSRequest(String awsConfigNameOrSecretKey, String method, String canonicalURI, String host, String service, String region, String payload, Map<String,String> headers, Map<String,String> params) {
        String request = createSignedAWSRequest(awsConfigNameOrSecretKey, method, canonicalURI, host, service, region, payload, headers, params, getCurrentDate());
        return request;
    }

    private String encode(String message){
        return EncodingUtil.urlEncode(message,'UTF-8').replace('+', '%20').replace('*', '%2A').replace('%7E','~');
    }
    private String getCurrentDate() {
        return DateTime.now().formatGmt('yyyy-MM-dd\'T\'HH:mm:ss.SSSZ');
    }
    
    private String getSHA256Digest (String payload) {
        String algorithmName = 'SHA-256';
        Blob input = Blob.valueOf(payload);
        Blob signing = Crypto.generateDigest(algorithmName, input);
        return signing.toString();
    }
    
    private String getSHA256HexDigest (String payload) {
        String algorithmName = 'SHA-256';
        Blob input = Blob.valueOf(payload);
        Blob signing = Crypto.generateDigest(algorithmName, input);
        return EncodingUtil.convertToHex(signing).toLowerCase();
    }

    private Blob getMac(String payload, String secretkey) {
        String algorithmName = 'hmacSHA256';
        Blob input = Blob.valueOf(payload);
        Blob key = Blob.valueOf(secretkey);
        Blob signing = Crypto.generateMac(algorithmName, input, key);
        //return signing.toString();
        return signing;
    }

    private Blob getMac(String payload, Blob secretkey) {
        String algorithmName = 'hmacSHA256';
        Blob input = Blob.valueOf(payload);
        Blob key = secretkey;
        Blob signing = Crypto.generateMac(algorithmName, input, key);
        //return signing.toString();
        return signing;
    }
    
    private String deriveSigningKey(String awsConfigNameOrSecretKey, String shortDate, String region, String service, String stringToSign) {
        String secretKey;
        List<charterforce__AWS_Config__c> aws = [SELECT charterforce__accessKey__c,
            charterforce__secretKey__c,
            charterforce__host__c,
            charterforce__queue__c
            FROM charterforce__AWS_Config__c
            WHERE name = :awsConfigNameOrSecretKey LIMIT 1];
        
        if (aws.size() > 0) {
            secretKey = aws[0].charterforce__secretKey__c;        
        } else {
            secretKey = awsConfigNameOrSecretKey;
        }
        
        Blob kDate = getMac(shortDate, 'AWS4' + secretKey);
        Blob kRegion = getMac(region, kDate);
        Blob kService = getMac(service, kRegion);
        Blob kSigning = getMac('aws4_request', kService);
        Blob kSignature = getMac(stringToSign, kSigning);
        String signature = EncodingUtil.convertToHex(kSignature).toLowerCase();
        
        return signature;
    }
    
    public void sendSQSMessage(String awsConfigNameOrSecretKey, String canonicalURI, String host, String service, String region, String message) { 
        Map<String,String> headers = new Map<String,String>();
        headers.put('host', host);
        headers.put('x-amz-date', getCurrentDate());

        Map<String,String> params = new Map<String,String>();
        params.put('Action','SendMessage');
        params.put('MessageBody',encode(message));
        params.put('Version','20121105');
        
        String request = createSignedAWSRequest(awsConfigNameOrSecretKey, 'GET', canonicalURI, host, service, region, message, headers, params);
        System.debug(request);
    }
}
