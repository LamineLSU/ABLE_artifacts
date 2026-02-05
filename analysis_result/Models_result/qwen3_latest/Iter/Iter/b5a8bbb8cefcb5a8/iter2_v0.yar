rule ProcessTermination
{
    meta:
        description = "Detects process termination logic via API calls and stack setup"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 85

    strings:
        $a = { 55 8B EC FF 75 08 }  // push ebp, mov ebp, esp, push [ebp+08h]
        $b = { E8 ?? ?? ?? ?? }     // indirect call to ___crtCorExitProcess
        $c = { FF 15 ?? ?? ?? ?? }  // call to ExitProcess (kernel32!ExitProcess)

    condition:
        all of them
}