Attribute VB_Name = "Filter"
'
' Simple Inbox Filter Script - Kyle Smith 08/12/2022
'
' To use:
' 1) Enable Developer mode
' 2) Set Trust Center Settings to Notify for all macros
' 3) Restart Outlook
' 4) Rules > Manage Rules & Alerts
' 5) Create a rule that runs a script on all incoming mail (have to enable the run a script rule in registry)
' 6) Run the script (Remember to include subfolders)!
'

Sub FilterMail(Item As Outlook.MailItem)
    With Item
        Dim ns As Outlook.NameSpace
        Dim MailDest As Outlook.Folder
        Set ns = Application.GetNamespace("MAPI")
        
        ' Tickets
    
        Set Reg1 = CreateObject("VBScript.RegExp")
        Reg1.Global = True
        Reg1.Pattern = "it@helios.net"

        If Reg1.Test(Item.Sender.GetExchangeUser.PrimarySmtpAddress) Then
            Set MailDest = ns.Folders("ks@helios.net").Folders("Inbox").Folders("Tickets")
            Item.Move MailDest
        End If
        
        ' Internal
    
        Set Reg2 = CreateObject("VBScript.RegExp")
        Reg2.Global = True
        Reg2.Pattern = "(.@helios\.net|.@helios\.net|.@icarus\.net)"

        If Reg2.Test(Item.Sender.GetExchangeUser.PrimarySmtpAddress) Then
            Set MailDest = ns.Folders("ks@helios.net").Folders("Inbox").Folders("Internal")
            Item.Move MailDest
        End If
    End With
End Sub
