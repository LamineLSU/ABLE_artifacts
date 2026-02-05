rule Targeted_Functionality  
{  
    meta:  
        confidence = 70  
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:  
        $a = { 55 8B EC FF 75 08 }  // Setup code  
        $b = { E8 C8 FF FF FF 59 }  // CRT call + pop ecx  
        $c = { FF 15 AC B0 41 00 }   // ExitProcess call  
    condition:  
        all of them  
}