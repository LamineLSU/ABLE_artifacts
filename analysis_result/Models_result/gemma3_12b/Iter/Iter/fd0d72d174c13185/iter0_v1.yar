rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - CALL instruction 2"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 50 E8 E3 FA FF FF }

    condition:
        any of them
}