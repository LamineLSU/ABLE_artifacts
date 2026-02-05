rule MaliciousExitSequence
{
    meta:
        description = "Detects a sequence of instructions leading to process termination, possibly indicating malicious exit behavior."
        cape_options = "bp0=$call_crt+0,action0=skip,bp1=$setup_code+0,action1=skip,bp2=$call_exit+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-03-15"

    strings:
        // Pattern 1: Call to __crtCorExitProcess followed by pop ecx
        $call_crt = { E8 C8 FF FF FF 59 }

        // Pattern 2: Push ebp, mov ebp, esp, push [ebp+08h]
        $setup_code = { 55 8B EC FF 75 08 }

        // Pattern 3: Call to ExitProcess (with offset)
        $call_exit = { FF 15 AC B0 41 00 }

    condition:
        $call_crt or $setup_code or $call_exit
}