rule Bypass_Evasion {
    meta:
        description = "Bypasss ExitProcess call using displacement instructions"
        cape_options = "bp0=E8C8???+0,action0=skip,bp1=75FF???+2,action1=skip,bp2=8BEC???+3,count=0"

    strings:
        $pattern0 = { E8 C8 ?? ?? ?? ?? }
        $pattern1 = { 75 FF ?? ?? ?? ?? }
        $pattern2 = { 8B EC ?? ?? ?? ?? }

    condition:
        any of them
}