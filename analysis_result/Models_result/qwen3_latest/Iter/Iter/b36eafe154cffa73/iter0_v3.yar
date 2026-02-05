rule Evasion_VirtualAllocExNuma_ExitProcess
{
    meta:
        description = "Malware uses VirtualAllocExNuma to detect sandboxed environments and calls ExitProcess on failure."
        author = "YourName"
        date = "2025-04-05"

    strings:
        $call_virtualalloc = /call\s+VirtualAllocExNuma/i
        $cmp_zero = /cmp\s+byte\s+ptr\s+\[ebp-\x04h\],\s+0/i
        $jne = /jne\s+0x[0-9A-F]+/i
        $exitprocess = /call\s+ExitProcess/i

    condition:
        all of them
            $jne
            $exitprocess
}