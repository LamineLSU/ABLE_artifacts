rule Bypass_Push_Call
{
    meta:
        description = "Bypass push and call sequence"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 00 40 E7 F0 55 8B EC FF 75 08 }

    condition:
        $pattern0
}