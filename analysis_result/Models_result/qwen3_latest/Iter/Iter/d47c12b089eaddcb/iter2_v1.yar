rule SandboxDetection
{
    meta:
        description = "Detects sandboxed execution by identifying key code patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 55 8B EC FF 75 08 }  // Stack frame setup
        $b = { E8 ?? ?? ?? ?? }     // Call to CRT function (___crtCorExitProcess)
        $c = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess (common in sandbox detection)

    condition:
        all of them
}