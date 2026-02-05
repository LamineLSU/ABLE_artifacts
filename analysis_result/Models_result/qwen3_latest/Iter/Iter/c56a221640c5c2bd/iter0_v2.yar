rule ExitProcessCall
{
    meta:
        description = "Call to ExitProcess"
        cape_options = "bp0=$call+0,action0=skip,bp1=$address+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $call = { FF 14 24 }  // "call eax" (assuming 32-bit architecture)
        $address = { 77 78 36 40 }  // Example address for ExitProcess in Windows 10

    condition:
        $call and $address
}