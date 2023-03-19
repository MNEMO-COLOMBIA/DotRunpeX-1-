rule detect_dotrunpex {
    meta:
        description = "Detects the presence of the DotRunpeX malware."
        author = "Fevar54"
        reference = "https://research.checkpoint.com/2023/dotrunpex-demystifying-new-virtualized-net-injector-used-in-the-wild/"
    strings:
        $product_name = "ProductName: RunpeX.Stub.Framework."
    condition:
        $product_name and any of them
}
