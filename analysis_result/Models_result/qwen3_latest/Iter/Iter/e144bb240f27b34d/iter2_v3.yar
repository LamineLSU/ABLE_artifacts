rule Evasion_Control_Flow  
{  
    meta:  
        description = "Detects evasion via control flow manipulation"  
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:  
        $a = { E8 C8 FF FF FF 59 } // Call to ___crtCorExitProcess + pop ecx  
        $b = { FF 15 AC B0 41 00 } // Direct call to ExitProcess  
        $c = { 8B FF 55 8B EC FF 75 08 } // Stack setup + push [ebp+08h]  
    condition:  
        all of ($a, $b, $c)  
}