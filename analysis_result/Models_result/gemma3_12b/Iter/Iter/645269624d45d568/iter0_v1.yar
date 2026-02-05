rule Bypass_CMP
{
    meta:
        description = "Bypass CMP instruction"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 64 A1 30 00 00 00 }

    condition:
        any of them
}