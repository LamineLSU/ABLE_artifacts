rule Bypass_Final_Call_3
{
    meta:
        description = "Bypass the final call at 013CA2FF"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 6A 03 FF 15 84 A0 41 01 }

    condition:
        any of them
}