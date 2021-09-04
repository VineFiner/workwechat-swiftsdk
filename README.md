# workwechat-swiftsdk

```
// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "YourProject",
    dependencies: [
    .package(url: "https://github.com/VineFiner/workwechat-swiftsdk.git", .branch("main"))
    ],
    targets: [
        .target(
            name: "YourTarget",
            dependencies: [
                .product(name: "WorkWechatSwiftsdk", package: "workwechat-swiftsdk")
            ]),
    ]
)

```
