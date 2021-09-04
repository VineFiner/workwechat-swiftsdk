//
//  File.swift
//  
//
//  Created by Finer  Vine on 2021/8/5.
//

import Foundation
import AsyncHTTPClient
import Logging
import NIO

public final class NormalClient {
    var request: NormalRequest
    
    public init(credentials: OAuthAccountCredentials,  httpClient: HTTPClient, eventLoop: EventLoop, logger: Logger) {
        let refreshableToken = OAuthCredentialLoader.getRefreshableToken(credentials: credentials,
                                                                         andClient: httpClient,
                                                                         eventLoop: eventLoop)
        request = NormalRequest(httpClient: httpClient, eventLoop: eventLoop, oauth: refreshableToken)
    }
    /// Hop to a new eventloop to execute requests on.
    /// - Parameter eventLoop: The eventloop to execute requests on.
    public func hopped(to eventLoop: EventLoop) -> NormalClient {
        request.eventLoop = eventLoop
        return self
    }
}

extension NormalClient {
    
    var endpoint: String {
        return "https://qyapi.weixin.qq.com"
    }
    
    // 推送信息
    public func pushMessageInfo(data: Data) -> EventLoopFuture<MessageSendResult> {
        let url = "\(endpoint)/cgi-bin/message/send"
        let requestBody = data
        return request.send(method: .POST, path: url, body: .data(requestBody))
    }
}
