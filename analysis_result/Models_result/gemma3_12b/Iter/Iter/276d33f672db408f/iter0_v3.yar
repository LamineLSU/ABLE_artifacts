rule Bypass_CALL_EAX
{
    meta:
        description = "Bypass CALL eax"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 8B 06 ?? 83 C4 14 52 8B 55 0C FF D0 }

    condition:
        any of them
}