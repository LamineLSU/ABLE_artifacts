rule ExitProcess_Call
{
    meta:
        description = "Detects a call to ExitProcess, commonly used in malicious code to terminate a process."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        tags = ["malware", "exitprocess", "process-termination"]

    strings:
        $a = { 8B 06 }        // MOV EAX, [ESI]
        $b = { FF D0 }        // CALL EAX

    condition:
        $a and $b
}