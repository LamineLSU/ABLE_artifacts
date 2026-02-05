rule Bypass_E8C1FFFFFF_Call_Unknown OFFSET=0x00
{
    meta:
        description = "Bypass E8C1FFFFFF with call to unknown offset"
        cape_options = "bp0=$pattern6+0,action0=skip,bp1=$pattern7+0,action1=skip,bp2=$pattern8+0,action2=skip,count=0"

    strings:
        $pattern6 = { 55 EB 8B EC EB FF 35 10 93 52 00 C1 5F CE CA AE }
    
    condition:
        any of them
}