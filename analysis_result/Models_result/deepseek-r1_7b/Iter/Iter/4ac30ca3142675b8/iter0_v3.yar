rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass after EAX test"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { ?? ?? ?? ?? ?? 5E ?? }   // Skipping FFD0
        $pattern1 = { ?? ?? ?? ?? 5D ?? }     // Skipping after FFD0
        $pattern2 = { ?? ?? ?? ?? C3 ?? ?? ?? ?? ?? } // Skipping ret after bypassed call
}

condition:
    any of them
}