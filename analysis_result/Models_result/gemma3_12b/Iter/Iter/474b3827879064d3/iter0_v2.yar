rule Bypass_Sample_Pattern1
{
    meta:
        description = "Bypass first CALL"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 50 FF 15 88 A0 31 00 }

    condition:
        any of them
}