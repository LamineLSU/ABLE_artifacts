rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting early checks and exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C0 74 12 48 5F 2D }  // TEST EAX followed by JE with specific offset
        $pattern1 = { C0 74 12 48 63 2E }   // Another occurrence of TEST EAX with modified offset
        $pattern2 = { 8B 4D 5F 2F 9C 5E }  // Sequence after RDPush for exit bypass
}

condition:
    (any of them)
}