rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Pattern 1"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }

    condition:
        any of them
}