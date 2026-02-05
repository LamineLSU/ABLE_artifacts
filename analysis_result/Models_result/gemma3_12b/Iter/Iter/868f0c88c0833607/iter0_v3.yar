rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass - Call 1"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 }

    condition:
        any of them
}