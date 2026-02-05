rule ExitDecisionPoint  
{  
    meta:  
        description = "Detects code leading to ExitProcess call"  
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 70  
    strings:  
        $a = { FF 75 08 E8 ?? ?? ?? ?? }  
        $b = { FF 15 AC B0 41 00 }  
        $c = { E8 ?? ?? ?? ?? 59 }  
    condition:  
        any of ($a, $b, $c)  
}