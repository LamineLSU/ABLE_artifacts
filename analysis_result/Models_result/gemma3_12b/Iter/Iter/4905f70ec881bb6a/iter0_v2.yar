rule Bypass_Sample_1
{
    meta:
        description = "Bypass Call instruction in Trace 1"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 88 A0 22 01 53 }

    condition:
        any of them
}