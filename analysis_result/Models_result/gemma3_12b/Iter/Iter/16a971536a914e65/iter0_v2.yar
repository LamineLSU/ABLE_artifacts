rule Bypass_Sample_Pattern1
{
    meta:
        description = "Bypass CALL to 0x44B9"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 33 C9 E8 4B 17 00 00 85 C0 }

    condition:
        all of them
}