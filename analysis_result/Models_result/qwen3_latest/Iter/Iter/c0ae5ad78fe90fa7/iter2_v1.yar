rule ExitChainEvasion
{
    meta:
        description = "Targets evasion logic leading to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "ThreatIntel"
        date = "2023-10-05"
    
    strings:
        $a = { E8 C8 ?? ?? ?? ?? } // Call to ___crtCorExitProcess
        $b = { FF 15 64 10 41 00 } // Call to ExitProcess
        $c = { FF 75 08 FF 15 64 10 41 00 } // Push + call to ExitProcess
    
    condition:
        all of ($a, $b, $c)
}