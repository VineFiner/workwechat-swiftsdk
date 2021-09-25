//
//  File.swift
//  
//  https://developer.apple.com/documentation/xctest
//  Created by Finer  Vine on 2021/10/3.
//

import XCTest
@testable import WorkWechatSDK
@testable import Logging

final class JsonMsgCryptTests: XCTestCase {
    
    let logger = Logger(label: "JsonMsgCryptTests")
    let corp_id = "wx5823bf96d3bd56c7"
    let encoding_token = "QDG6eK"
    let encoding_aesKey = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
    let timeStamp = "1409659813"
    let nonce = "1372623149"

    // 测试验证URL
    func testVerifyURL() throws {
        let msgSignature = "477715d11cdb4164915debcba66cb864d751f3e6"
        let echostr = "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q=="
        
        let cpt = try WXBizJsonMsgCrypt(sToken: encoding_token, sEncodingAESKey: encoding_aesKey, sReceiveId: corp_id, logger: logger)
        let verifyString = cpt.calSignature(timeStamp: timeStamp, nonce: nonce, data: echostr)
        XCTAssertEqual(verifyString, msgSignature)
    }
    
    func testVerifyURLPerformance() throws {
        
        let echostr = "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q=="
        
        let cpt = try WXBizJsonMsgCrypt(sToken: encoding_token, sEncodingAESKey: encoding_aesKey, sReceiveId: corp_id, logger: logger)
        
        self.measure {
            _ = cpt.calSignature(timeStamp: timeStamp, nonce: nonce, data: echostr)
        }
    }
    
    // 测试解密函数
    func testDecryptMsg() throws {
        let msgSignature = "477715d11cdb4164915debcba66cb864d751f3e6"
        let msgEncrypt = "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q=="
        
        let cpt = try WXBizJsonMsgCrypt(sToken: encoding_token, sEncodingAESKey: encoding_aesKey, sReceiveId: corp_id, logger: logger)
        let msg =  try cpt.decryptMsg(msgSignature: msgSignature, timeStamp: "\(timeStamp)", nonce: nonce, msgEncrypt: msgEncrypt)
        let original = """
        <xml><ToUserName><![CDATA[wx5823bf96d3bd56c7]]></ToUserName>
        <FromUserName><![CDATA[mycreate]]></FromUserName>
        <CreateTime>1409659813</CreateTime>
        <MsgType><![CDATA[text]]></MsgType>
        <Content><![CDATA[hello]]></Content>
        <MsgId>4561255354251345929</MsgId>
        <AgentID>218</AgentID>
        </xml>
        """
        XCTAssertEqual(msg, original)
    }

    func testDecryptMsgPerformance() throws {
        let msgSignature = "477715d11cdb4164915debcba66cb864d751f3e6"
        let msgEncrypt = "RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q=="
        
        let cpt = try WXBizJsonMsgCrypt(sToken: encoding_token, sEncodingAESKey: encoding_aesKey, sReceiveId: corp_id, logger: logger)
        self.measure {
            _ = try? cpt.decryptMsg(msgSignature: msgSignature, timeStamp: "\(timeStamp)", nonce: nonce, msgEncrypt: msgEncrypt)
        }
    }
    
    // 测试加密函数
    func testEncryptMsg() throws {
        
        let msgEncrypt = "6ofDt14638gb89hvN6jHuBdhOUzSfsp6trb822Fg4tbbllRNn3Vcc4k7sjszSfJbkYNkwjHU572dg2mcsgKt6Q/B3VPVFtitxfk3qekSEXgdcXnKfT/RI1Mb3mkI3hiTowZUF4sg0EafM5ifo6Y2Q+SQDlL30TezPq1MjQyg3FSBUsXjfLviN6+TdsCmu1ihX6TLpyKKIDtEAVNrNWFHsgmsThEz2He2Zz8m5xehoyDUtAdYio1f33mtQ6qyXuTPMf7V7Z8KG3wqbbiwsZ7yyM43YRMBWxgVFy396bA59QKlt6vDkHIvw/FakSDIKPQhA3flCP4NBs05aSLoc9niVhXhGqTl8S9nz9AVU+UbyQpPf8QxVYPsIXFR+rxRHPzYK4HeDDBcU/2t2l6t4YCzNVm7E8k2i/PPcICoYeL0XUYxpaL9isOtVcNLVxsMg7xDQcPsmT5T/vk3PnFWJr9K2A=="
        let original = "<xml><ToUserName><![CDATA[mycreate]]></ToUserName><FromUserName><![CDATA[wx5823bf96d3bd56c7]]></FromUserName><CreateTime>1348831860</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[this is a test]]></Content><MsgId>1234567890123456</MsgId><AgentID>128</AgentID></xml>"
        
        let cpt = try WXBizJsonMsgCrypt(sToken: encoding_token, sEncodingAESKey: encoding_aesKey, sReceiveId: corp_id, logger: logger)
        let xmlContent = try cpt.encryptMsg(replyMsg: original, timestamp: "\(timeStamp)", nonce: nonce).xmlContent
        XCTAssertEqual(xmlContent, msgEncrypt)
        let signature = try cpt.encryptMsg(replyMsg: original, timestamp: timeStamp, nonce: nonce).signature
        XCTAssertEqual(signature, "6eee3349aa2c33f67f649d136d507ed3d7a4afb4")
    }
}
