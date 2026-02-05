rule Bypass_Sample_Pattern1
{
    meta:
        description = "Bypass conditional jump at 001BA29B"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 20 00 }

    condition:
        any of them
}