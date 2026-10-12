//
//  AceESPView.swift  —  ESP 控制页
//

import SwiftUI

struct AceESPView: View {
    @State private var processName: String = AceESP.shared().targetProcess
    @State private var running: Bool = false
    @State private var busy: Bool = false
    @State private var playerCount: Int = 0
    @State private var logs: [String] = []
    @State private var poller: Timer? = nil

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                HStack {
                    Text("目标进程").font(.headline)
                    Spacer()
                }
                TextField("可执行文件名，例如 heroios", text: $processName)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)

                HStack(spacing: 10) {
                    Button {
                        if running { stop() } else { start() }
                    } label: {
                        HStack {
                            if busy {
                                ProgressView().tint(.white)
                            } else {
                                Image(systemName: running ? "stop.circle.fill" : "play.circle.fill")
                            }
                            Text(busy ? "初始化中…" : (running ? "停止 ESP" : "启动 ESP"))
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(running ? Color.red.opacity(0.85) : Color.accentColor)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .disabled(busy)

                    Button {
                        AceESP.shared().listProcessesAsync()
                    } label: {
                        Image(systemName: "list.bullet.rectangle")
                            .padding(.vertical, 14)
                            .padding(.horizontal, 16)
                            .background(Color.secondary.opacity(0.18))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .disabled(busy)
                }

                HStack {
                    Circle()
                        .fill(running ? Color.green : Color.gray)
                        .frame(width: 10, height: 10)
                    Text(busy ? "初始化中" : (running ? "运行中" : "未运行"))
                    Spacer()
                    Text("实体 \(playerCount)").foregroundStyle(.secondary)
                }
                .font(.subheadline)

                Divider()

                HStack {
                    Text("日志").font(.headline)
                    Spacer()
                    Button("清空") { logs.removeAll() }.font(.caption)
                }

                ScrollView {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(logs.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(8)
                }
                .background(Color.secondary.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 10))

                Text("进程名是可执行文件名，不是 Bundle ID。不确定就点右上角列表按钮查。初始化十几秒属正常，期间界面不会卡。")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .navigationTitle("ESP")
            .onAppear {
                // ⚠️ logBlock 来自后台串行队列，必须切主线程再改 @State
                AceESP.shared().logBlock = { line in
                    DispatchQueue.main.async {
                        logs.append(line)
                        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
                    }
                }
                running = AceESP.shared().running
                startPolling()
            }
            .onDisappear {
                poller?.invalidate()
                poller = nil
            }
        }
    }

    private func start() {
        busy = true
        AceESP.shared().targetProcess = processName
        // 异步：所有内核/远程调用都在内部串行队列上跑，不阻塞主线程
        AceESP.shared().startAsync { ok in
            busy = false
            running = ok
            if !ok {
                appendLog("启动失败：看上面日志判断卡在哪一步")
            } else {
                AceESP.shared().dumpOnceAsync()
            }
        }
    }

    private func stop() {
        AceESP.shared().stop()
        running = false
        playerCount = 0
    }

    private func appendLog(_ s: String) {
        logs.append(s)
        if logs.count > 500 { logs.removeFirst(logs.count - 500) }
    }

    private func startPolling() {
        poller?.invalidate()
        poller = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            playerCount = Int(AceESP.shared().lastPlayerCount)
            if !busy { running = AceESP.shared().running }
        }
    }
}
