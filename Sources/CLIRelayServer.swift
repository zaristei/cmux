import CryptoKit
import Darwin
import Foundation
import Network

final class CLIRelayServer {
    private final class Session {
        private enum Phase {
            case awaitingProtocolDetection
            case awaitingAuth
            case awaitingCommand
            case forwarding
            case closed
        }

        private let connection: NWConnection
        private let localSocketPath: String
        private let relayID: String
        private let relayToken: Data
        private let queue: DispatchQueue
        private let onClose: () -> Void
        private let challengeProtocol = "cmux-relay-auth"
        private let challengeVersion = 1
        private let minimumFailureDelay: TimeInterval = 0.05
        private let maximumFrameBytes = 64 * 1024

        private var buffer = Data()
        private var phase: Phase = .awaitingProtocolDetection
        private var challengeNonce = ""
        private var challengeSentAt = Date()
        private var isClosed = false

        init(
            connection: NWConnection,
            localSocketPath: String,
            relayID: String,
            relayToken: Data,
            queue: DispatchQueue,
            onClose: @escaping () -> Void
        ) {
            self.connection = connection
            self.localSocketPath = localSocketPath
            self.relayID = relayID
            self.relayToken = relayToken
            self.queue = queue
            self.onClose = onClose
        }

        func start() {
            connection.stateUpdateHandler = { [weak self] state in
                self?.queue.async {
                    self?.handleState(state)
                }
            }
            connection.start(queue: queue)
        }

        func stop() {
            close()
        }

        private func handleState(_ state: NWConnection.State) {
            guard !isClosed else { return }
            switch state {
            case .ready:
                challengeSentAt = Date()
                receive()
            case .failed, .cancelled:
                close()
            default:
                break
            }
        }

        private func sendChallenge() {
            challengeSentAt = Date()
            challengeNonce = Self.randomHex(byteCount: 16)
            let challenge: [String: Any] = [
                "protocol": challengeProtocol,
                "version": challengeVersion,
                "relay_id": relayID,
                "nonce": challengeNonce,
            ]
            sendJSONLine(challenge) { _ in }
        }

        private func receive() {
            guard !isClosed else { return }
            connection.receive(minimumIncompleteLength: 1, maximumLength: maximumFrameBytes) { [weak self] data, _, isComplete, error in
                guard let self else { return }
                self.queue.async {
                    if error != nil {
                        self.close()
                        return
                    }
                    if let data, !data.isEmpty {
                        self.buffer.append(data)
                        if self.buffer.count > self.maximumFrameBytes {
                            self.sendFailureAndClose()
                            return
                        }
                        self.processBufferedLines()
                    }
                    if isComplete {
                        self.close()
                        return
                    }
                    if !self.isClosed {
                        self.receive()
                    }
                }
            }
        }

        private func processBufferedLines() {
            // Protocol detection: check first bytes to determine HTTP vs raw relay
            if phase == .awaitingProtocolDetection {
                guard buffer.count >= 4 else { return }
                if buffer.starts(with: Data("POST".utf8)) || buffer.starts(with: Data("GET ".utf8)) {
                    handleHTTPRequest()
                    return
                }
                // Raw relay protocol — send challenge and switch to auth phase
                phase = .awaitingAuth
                sendChallenge()
            }

            while let newlineIndex = buffer.firstIndex(of: 0x0A), !isClosed {
                let lineData = buffer.prefix(upTo: newlineIndex)
                buffer.removeSubrange(...newlineIndex)
                let line = String(data: lineData, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                switch phase {
                case .awaitingProtocolDetection:
                    return
                case .awaitingAuth:
                    handleAuthLine(line)
                case .awaitingCommand:
                    handleCommandLine(Data(lineData) + Data([0x0A]))
                case .forwarding, .closed:
                    return
                }
            }
        }

        private func handleAuthLine(_ line: String) {
            guard let data = line.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let receivedRelayID = object["relay_id"] as? String,
                  receivedRelayID == relayID,
                  let macHex = object["mac"] as? String,
                  let receivedMAC = Self.hexData(from: macHex)
            else {
                sendFailureAndClose()
                return
            }

            let message = Self.authMessage(relayID: relayID, nonce: challengeNonce, version: challengeVersion)
            let expectedMAC = Self.authMAC(token: relayToken, message: message)
            guard Self.constantTimeEqual(receivedMAC, expectedMAC) else {
                sendFailureAndClose()
                return
            }

            phase = .awaitingCommand
            sendJSONLine(["ok": true]) { [weak self] _ in
                self?.queue.async {
                    self?.processBufferedLines()
                }
            }
        }

        private func handleCommandLine(_ commandLine: Data) {
            guard !commandLine.isEmpty else {
                sendFailureAndClose()
                return
            }
            phase = .forwarding
            DispatchQueue.global(qos: .utility).async { [localSocketPath, commandLine, queue] in
                let result = Result { try Self.roundTripUnixSocket(socketPath: localSocketPath, request: commandLine) }
                queue.async { [weak self] in
                    guard let self else { return }
                    switch result {
                    case .success(let response):
                        self.connection.send(content: response, completion: .contentProcessed { [weak self] _ in
                            self?.queue.async {
                                self?.close()
                            }
                        })
                    case .failure:
                        self.sendFailureAndClose()
                    }
                }
            }
        }

        // MARK: - HTTP POST handler

        private func handleHTTPRequest() {
            phase = .forwarding

            // Wait until we have the full HTTP request (headers + body)
            // Look for \r\n\r\n to find end of headers
            guard let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else {
                // Need more data — keep receiving, re-check on next receive
                phase = .awaitingProtocolDetection
                return
            }

            let headerData = buffer.prefix(upTo: headerEnd.lowerBound)
            let bodyStart = headerEnd.upperBound

            guard let headerString = String(data: headerData, encoding: .utf8) else {
                sendHTTPResponse(status: 400, body: "{\"ok\":false,\"error\":\"invalid headers\"}")
                return
            }

            // Parse Content-Length
            var contentLength = 0
            for line in headerString.split(separator: "\r\n") {
                let lower = line.lowercased()
                if lower.hasPrefix("content-length:") {
                    let value = line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)
                    contentLength = Int(value) ?? 0
                }
            }

            let bodyAvailable = buffer.count - bodyStart
            guard bodyAvailable >= contentLength else {
                // Need more body data
                phase = .awaitingProtocolDetection
                return
            }

            let bodyData = buffer[bodyStart..<(bodyStart + contentLength)]

            // Parse JSON body: {"relay_id": "...", "mac": "...", "nonce": "...", "command": "..."}
            guard let json = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any],
                  let receivedRelayID = json["relay_id"] as? String,
                  receivedRelayID == relayID,
                  let macHex = json["mac"] as? String,
                  let receivedMAC = Self.hexData(from: macHex),
                  let nonce = json["nonce"] as? String, !nonce.isEmpty,
                  let command = json["command"] as? String, !command.isEmpty
            else {
                sendHTTPResponse(status: 401, body: "{\"ok\":false,\"error\":\"invalid request\"}")
                return
            }

            // Verify HMAC using the client-provided nonce
            let message = Self.authMessage(relayID: relayID, nonce: nonce, version: challengeVersion)
            let expectedMAC = Self.authMAC(token: relayToken, message: message)
            guard Self.constantTimeEqual(receivedMAC, expectedMAC) else {
                sendHTTPResponse(status: 401, body: "{\"ok\":false,\"error\":\"auth failed\"}")
                return
            }

            // Forward command to Unix socket
            let commandData = Data((command.hasSuffix("\n") ? command : command + "\n").utf8)
            DispatchQueue.global(qos: .utility).async { [localSocketPath, queue] in
                let result = Result { try Self.roundTripUnixSocket(socketPath: localSocketPath, request: commandData) }
                queue.async { [weak self] in
                    guard let self else { return }
                    switch result {
                    case .success(let response):
                        let responseString = String(data: response, encoding: .utf8) ?? ""
                        self.sendHTTPResponse(status: 200, body: responseString)
                    case .failure:
                        self.sendHTTPResponse(status: 502, body: "{\"ok\":false,\"error\":\"upstream failed\"}")
                    }
                }
            }
        }

        private func sendHTTPResponse(status: Int, body: String) {
            let statusText: String
            switch status {
            case 200: statusText = "OK"
            case 400: statusText = "Bad Request"
            case 401: statusText = "Unauthorized"
            case 502: statusText = "Bad Gateway"
            default: statusText = "Error"
            }
            let bodyData = Data(body.utf8)
            let header = "HTTP/1.1 \(status) \(statusText)\r\nContent-Type: application/octet-stream\r\nContent-Length: \(bodyData.count)\r\nConnection: close\r\n\r\n"
            let payload = Data(header.utf8) + bodyData
            connection.send(content: payload, completion: .contentProcessed { [weak self] _ in
                self?.queue.async {
                    self?.close()
                }
            })
        }

        // MARK: - Raw relay failure

        private func sendFailureAndClose() {
            let elapsed = Date().timeIntervalSince(challengeSentAt)
            let delay = max(0, minimumFailureDelay - elapsed)
            phase = .closed
            queue.asyncAfter(deadline: .now() + delay) { [weak self] in
                self?.sendJSONLine(["ok": false]) { [weak self] _ in
                    self?.queue.async {
                        self?.close()
                    }
                }
            }
        }

        private func sendJSONLine(_ object: [String: Any], completion: @escaping (NWError?) -> Void) {
            guard !isClosed else {
                completion(nil)
                return
            }
            guard let payload = try? JSONSerialization.data(withJSONObject: object) else {
                completion(nil)
                return
            }
            connection.send(content: payload + Data([0x0A]), completion: .contentProcessed(completion))
        }

        private func close() {
            guard !isClosed else { return }
            isClosed = true
            phase = .closed
            connection.stateUpdateHandler = nil
            connection.cancel()
            onClose()
        }

        static func authMessage(relayID: String, nonce: String, version: Int) -> Data {
            Data("relay_id=\(relayID)\nnonce=\(nonce)\nversion=\(version)".utf8)
        }

        static func authMAC(token: Data, message: Data) -> Data {
            let key = SymmetricKey(data: token)
            let code = HMAC<SHA256>.authenticationCode(for: message, using: key)
            return Data(code)
        }

        static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
            guard lhs.count == rhs.count else { return false }
            var diff: UInt8 = 0
            for index in lhs.indices {
                diff |= lhs[index] ^ rhs[index]
            }
            return diff == 0
        }

        static func hexData(from string: String) -> Data? {
            let normalized = string.trimmingCharacters(in: .whitespacesAndNewlines)
            guard normalized.count.isMultiple(of: 2), !normalized.isEmpty else { return nil }
            var data = Data(capacity: normalized.count / 2)
            var cursor = normalized.startIndex
            while cursor < normalized.endIndex {
                let next = normalized.index(cursor, offsetBy: 2)
                guard let byte = UInt8(normalized[cursor..<next], radix: 16) else { return nil }
                data.append(byte)
                cursor = next
            }
            return data
        }

        static func randomHex(byteCount: Int) -> String {
            var bytes = [UInt8](repeating: 0, count: byteCount)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            return bytes.map { String(format: "%02x", $0) }.joined()
        }

        private static func roundTripUnixSocket(socketPath: String, request: Data) throws -> Data {
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else {
                throw NSError(domain: "cmux.remote.relay", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: "failed to create local relay socket",
                ])
            }
            defer { Darwin.close(fd) }

            var timeout = timeval(tv_sec: 15, tv_usec: 0)
            withUnsafePointer(to: &timeout) { pointer in
                _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
                _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
            }

            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            let pathBytes = Array(socketPath.utf8CString)
            guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
                throw NSError(domain: "cmux.remote.relay", code: 2, userInfo: [
                    NSLocalizedDescriptionKey: "local relay socket path is too long",
                ])
            }
            let sunPathOffset = MemoryLayout<sockaddr_un>.offset(of: \.sun_path) ?? 0
            withUnsafeMutableBytes(of: &address) { rawBuffer in
                let destination = rawBuffer.baseAddress!.advanced(by: sunPathOffset)
                pathBytes.withUnsafeBytes { pathBuffer in
                    destination.copyMemory(from: pathBuffer.baseAddress!, byteCount: pathBytes.count)
                }
            }

            let addressLength = socklen_t(MemoryLayout.size(ofValue: address.sun_family) + pathBytes.count)
            let connectResult = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, addressLength)
                }
            }
            guard connectResult == 0 else {
                throw NSError(domain: "cmux.remote.relay", code: 3, userInfo: [
                    NSLocalizedDescriptionKey: "failed to connect to local cmux socket",
                ])
            }

            try request.withUnsafeBytes { rawBuffer in
                guard let baseAddress = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return }
                var bytesRemaining = rawBuffer.count
                var pointer = baseAddress
                while bytesRemaining > 0 {
                    let written = Darwin.write(fd, pointer, bytesRemaining)
                    if written <= 0 {
                        throw NSError(domain: "cmux.remote.relay", code: 4, userInfo: [
                            NSLocalizedDescriptionKey: "failed to write relay request",
                        ])
                    }
                    bytesRemaining -= written
                    pointer = pointer.advanced(by: written)
                }
            }
            _ = shutdown(fd, SHUT_WR)

            var response = Data()
            var scratch = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = Darwin.read(fd, &scratch, scratch.count)
                if count > 0 {
                    response.append(scratch, count: count)
                    continue
                }
                if count == 0 {
                    break
                }

                if errno == EAGAIN || errno == EWOULDBLOCK {
                    if !response.isEmpty {
                        break
                    }
                    throw NSError(domain: "cmux.remote.relay", code: 5, userInfo: [
                        NSLocalizedDescriptionKey: "timed out waiting for local cmux response",
                    ])
                }
                throw NSError(domain: "cmux.remote.relay", code: 6, userInfo: [
                    NSLocalizedDescriptionKey: "failed to read local cmux response",
                ])
            }
            return response
        }
    }

    private let localSocketPath: String
    private let relayID: String
    private let relayToken: Data
    private let queue = DispatchQueue(label: "com.cmux.cli-relay.\(UUID().uuidString)", qos: .utility)

    private var listener: NWListener?
    private var sessions: [UUID: Session] = [:]
    private var isStopped = false
    private(set) var localPort: Int?

    init(localSocketPath: String, relayID: String, relayTokenHex: String) throws {
        guard let relayToken = Session.hexData(from: relayTokenHex), !relayToken.isEmpty else {
            throw NSError(domain: "cmux.remote.relay", code: 7, userInfo: [
                NSLocalizedDescriptionKey: "invalid relay token",
            ])
        }
        self.localSocketPath = localSocketPath
        self.relayID = relayID
        self.relayToken = relayToken
    }

    func start(host: String = "127.0.0.1", port: Int = 0) throws -> Int {
        if let existingPort = queue.sync(execute: { localPort }) {
            return existingPort
        }

        let listener = try Self.makeListener(host: host, port: port)
        let readySemaphore = DispatchSemaphore(value: 0)
        let stateLock = NSLock()
        var capturedError: Error?
        var boundPort: Int?

        listener.newConnectionHandler = { [weak self] connection in
            self?.queue.async {
                self?.acceptConnectionLocked(connection)
            }
        }
        listener.stateUpdateHandler = { listenerState in
            switch listenerState {
            case .ready:
                stateLock.lock()
                boundPort = listener.port.map { Int($0.rawValue) }
                stateLock.unlock()
                readySemaphore.signal()
            case .failed(let error):
                stateLock.lock()
                capturedError = error
                stateLock.unlock()
                readySemaphore.signal()
            default:
                break
            }
        }
        listener.start(queue: queue)

        let waitResult = readySemaphore.wait(timeout: .now() + 5.0)
        stateLock.lock()
        let startupError = capturedError
        let startupPort = boundPort
        stateLock.unlock()

        if waitResult != .success {
            listener.newConnectionHandler = nil
            listener.stateUpdateHandler = nil
            listener.cancel()
            throw NSError(domain: "cmux.remote.relay", code: 8, userInfo: [
                NSLocalizedDescriptionKey: "timed out waiting for local relay listener",
            ])
        }
        if let startupError {
            listener.newConnectionHandler = nil
            listener.stateUpdateHandler = nil
            listener.cancel()
            throw startupError
        }
        guard let startupPort, startupPort > 0 else {
            listener.newConnectionHandler = nil
            listener.stateUpdateHandler = nil
            listener.cancel()
            throw NSError(domain: "cmux.remote.relay", code: 8, userInfo: [
                NSLocalizedDescriptionKey: "failed to bind local relay listener",
            ])
        }

        return queue.sync {
            if let localPort {
                listener.newConnectionHandler = nil
                listener.stateUpdateHandler = nil
                listener.cancel()
                return localPort
            }
            self.listener = listener
            self.localPort = startupPort
            return startupPort
        }
    }

    func stop() {
        queue.sync {
            guard !isStopped else { return }
            isStopped = true
            listener?.newConnectionHandler = nil
            listener?.stateUpdateHandler = nil
            listener?.cancel()
            listener = nil
            localPort = nil
            let activeSessions = sessions.values
            sessions.removeAll()
            for session in activeSessions {
                session.stop()
            }
        }
    }

    private func acceptConnectionLocked(_ connection: NWConnection) {
        guard !isStopped else {
            connection.cancel()
            return
        }
        let sessionID = UUID()
        let session = Session(
            connection: connection,
            localSocketPath: localSocketPath,
            relayID: relayID,
            relayToken: relayToken,
            queue: queue
        ) { [weak self] in
            self?.sessions.removeValue(forKey: sessionID)
        }
        sessions[sessionID] = session
        session.start()
    }

    private static func makeListener(host: String = "127.0.0.1", port: Int = 0) throws -> NWListener {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcpOptions)
        parameters.allowLocalEndpointReuse = true
        let nwPort = port > 0 ? NWEndpoint.Port(rawValue: UInt16(port))! : .any
        if host == "0.0.0.0" {
            // Bind to all interfaces using the port-only NWListener initializer
            return try NWListener(using: parameters, on: nwPort)
        }
        parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: nwPort)
        return try NWListener(using: parameters)
    }
}
