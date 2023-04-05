Function Import-DLPCompliancePoliciesAndRule {
    <#
        .SYNOPSIS
            Import DLP compliance policies and rules

        .DESCRIPTION
            Import saved DLP compliance policies and rules and create them in a tenant

        .PARAMETER Upn
            Username with access to the Security and Compliance center

        .PARAMETER ImportPath
            Custom import path. Default is c:\Temp\DLP

        .EXAMPLE
           PS C:> Import-DLPCompliancePoliciesAndRules -Upn admin@tenant.onmicrosoft.com

           This will log on to the SCC endpoint as admin@tenant.onmicrosoft.com, import all DLP compliance policies and rules

        .NOTES
            None
    #>

    [cmdletbinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 1)]
        [string]
        $Upn,

        [string]
        $ImportPath = "c:\Temp\DLP"
    )

    begin {
        Write-Output "Starting"
    }

    process {
        try {
            Write-Output "Importing policies from: $($ImportPath)\DLPCompliancePolicies.json"
            $policiesFound = (Get-Content -Path "$($ImportPath)\DLPCompliancePolicies.json") | ConvertFrom-Json -AsHashtable -ErrorAction Stop

            Write-Output "Importing rules from: $($ImportPath)\DLPCompliancePolicyRules.json"
            $rulesFound = (Get-Content -Path "$($ImportPath)\DLPCompliancePolicyRules.json") | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Output "ERROR: $_"
            return
        }

        try {
            # Connect to the Security and Compliance endpoints
            Connect-IPPSSession -UserPrincipalName $Upn -ErrorAction Stop

            foreach ($currentPolicy in $policiesFound) {
                $policyParams = @{
                    Name                                  = $currentPolicy.Name
                    Comment                               = $currentPolicy.Comment
                    EndpointDlpLocation                   = $currentPolicy.EndpointDlpLocation
                    EndpointDlpLocationException          = $currentPolicy.EndpointDlpLocationException
                    ExceptIfOneDriveSharedBy              = $currentPolicy.EndpointDlpLocationException
                    ExceptIfOneDriveSharedByMemberOf      = $currentPolicy.EndpointDlpLocationException
                    ExchangeLocation                      = $currentPolicy.ExchangeLocation.Name
                    ExchangeSenderMemberOf                = $currentPolicy.ExchangeSenderMemberOf
                    ExchangeSenderMemberOfException       = $currentPolicy.ExchangeSenderMemberOfException
                    Mode                                  = $currentPolicy.Mode
                    OneDriveLocation                      = $currentPolicy.OneDriveLocation
                    OneDriveLocationException             = $currentPolicy.OneDriveLocationException
                    OneDriveSharedBy                      = $currentPolicy.EndpointDlpLocationException
                    OneDriveSharedByMemberOf              = $currentPolicy.EndpointDlpLocationException
                    OnPremisesScannerDlpLocation          = $currentPolicy.OnPremisesScannerDlpLocation
                    OnPremisesScannerDlpLocationException = $currentPolicy.OnPremisesScannerDlpLocationException
                    PolicyTemplateInfo                    = $currentPolicy.PolicyTemplateInfo
                    PowerBIDlpLocation                    = $currentPolicy.PowerBIDlpLocation
                    PowerBIDlpLocationException           = $currentPolicy.PowerBIDlpLocationException
                    Priority                              = $currentPolicy.Priority
                    SharePointLocation                    = $currentPolicy.SharePointLocation
                    SharePointLocationException           = $currentPolicy.SharePointLocationException
                    TeamsLocation                         = $currentPolicy.TeamsLocation
                    TeamsLocationException                = $currentPolicy.TeamsLocationException
                    ThirdPartyAppDlpLocation              = $currentPolicy.ThirdPartyAppDlpLocation
                    ThirdPartyAppDlpLocationException     = $currentPolicy.ThirdPartyAppDlpLocationException
                }

                Write-Verbose "Creating policy: $($policyParams.Name)"
                New-DlpCompliancePolicy @policyParams -ErrorAction SilentlyContinue -ErrorVariable PolicyErrors
            }

            Write-Output "Processing DLP compliance policy rules"
            foreach ($currentRule in $rulesFound) {
                if (-NOT($currentRule.DocumentSizeOver)) { $ruleDocumentSizeOver = '0' } else { $ruleDocumentSizeOver = $currentRule.DocumentSizeOver }
                if (-NOT($currentRule.MessageSizeOver)) { $ruleMessageSizeOver = '0' } else { $ruleMessageSizeOver = $currentRule.MessageSizeOver }

                Write-Verbose "Creating policy rule: $($ruleParams.Name)"
                New-DlpComplianceRule -Policy $currentRule.ParentPolicyName -Name $currentRule.Name -AdvancedRule $currentRule.AdvancedRule.ToString() -Verbose -ErrorAction Stop

                Write-Verbose "Setting policy rule properties on: $($ruleParams.Name)"
                Set-DlpComplianceRule -Identity $currentRule.Name -AccessScope $currentRule.AccessScope -ActivationDate $currentRule.ActivationDate -AddRecipients $currentRule.AddRecipients`
                    -AlertProperties @{AggregationType = $currentRule.AlertProperties.AggregationType.ToString() } -AnyOfRecipientAddressContainsWords $currentRule.AnyOfRecipientAddressContainsWords`
                    -AnyOfRecipientAddressMatchesPatterns $currentRule.AnyOfRecipientAddressMatchesPatterns -ApplyHtmlDisclaimer $currentRule.ApplyHtmlDisclaimer`
                    -Comment $currentRule.Comment -BlockAccess $currentRule.BlockAccess -BlockAccessScope $currentRule.BlockAccessScope -ContentCharacterSetContainsWords $currentRule.ContentCharacterSetContainsWords`
                    -ContentContainsSensitiveInformation $currentRule.ContentContainsSensitiveInformation -ContentExtensionMatchesWords $currentRule.ContentExtensionMatchesWords -ContentFileTypeMatches $currentRule.ContentFileTypeMatches`
                    -ContentIsNotLabeled $currentRule.ContentIsNotLabeled -ContentIsShared $currentRule.ContentIsShared -ContentPropertyContainsWords $currentRule.ContentPropertyContainsWords -Disabled $currentRule.Disabled`
                    -DocumentContainsWords $currentRule.DocumentContainsWords -DocumentCreatedBy $currentRule.DocumentCreatedBy -DocumentCreatedByMemberOf $currentRule.DocumentCreatedByMemberOf -DocumentIsPasswordProtected $currentRule.DocumentIsPasswordProtected`
                    -DocumentIsUnsupported $currentRule.DocumentIsUnsupported -DocumentNameMatchesPatterns $currentRule.DocumentNameMatchesPatterns -DocumentNameMatchesWords $currentRule.DocumentNameMatchesWords -DocumentSizeOver $ruleDocumentSizeOver -EncryptRMSTemplate $currentRule.EncryptRMSTemplate`
                    -EndpointDlpBrowserRestrictions $currentRule.EndpointDlpBrowserRestrictions -EndpointDlpRestrictions $currentRule.EndpointDlpRestrictions -ExceptIfAccessScope $currentRule.ExceptIfAccessScope -ExceptIfAnyOfRecipientAddressContainsWords $currentRule.ExceptIfAnyOfRecipientAddressContainsWords`
                    -ExceptIfAnyOfRecipientAddressMatchesPatterns $currentRule.ExceptIfAnyOfRecipientAddressMatchesPatterns -ExceptIfContentCharacterSetContainsWords $currentRule.ExceptIfContentCharacterSetContainsWords -ExceptIfContentContainsSensitiveInformation $currentRule.ExceptIfContentContainsSensitiveInformation`
                    -ExceptIfContentExtensionMatchesWords $currentRule.ExceptIfContentExtensionMatchesWords -ExceptIfContentFileTypeMatches $currentRule.ExceptIfContentFileTypeMatches -ExceptIfContentIsShared $currentRule.ExceptIfContentIsShared -ExceptIfContentPropertyContainsWords $currentRule.ExceptIfContentPropertyContainsWords`
                    -ExceptIfDocumentContainsWords $currentRule.ExceptIfDocumentContainsWords -ExceptIfDocumentCreatedBy $currentRule.ExceptIfDocumentCreatedBy -ExceptIfDocumentCreatedByMemberOf $currentRule.ExceptIfDocumentCreatedByMemberOf -ExceptIfDocumentIsPasswordProtected $currentRule.ExceptIfDocumentIsPasswordProtected`
                    -ExceptIfDocumentIsUnsupported $currentRule.ExceptIfDocumentIsUnsupported -ExceptIfDocumentMatchesPatterns $currentRule.ExceptIfDocumentMatchesPatterns -ExceptIfDocumentNameMatchesPatterns $currentRule.ExceptIfDocumentNameMatchesPatterns -ExceptIfDocumentNameMatchesWords $currentRule.ExceptIfDocumentNameMatchesWords -ExceptIfDocumentSizeOver '0'`
                    -ExceptIfFrom $currentRule.ExceptIfFrom -ExceptIfFromAddressContainsWords $currentRule.ExceptIfFromAddressContainsWords -ExceptIfFromAddressMatchesPatterns $currentRule.ExceptIfFromAddressMatchesPatterns -ExceptIfFromMemberOf $currentRule.ExceptIfFromMemberOf -ExceptIfFromScope $currentRule.ExceptIfFromScope`
                    -ExceptIfHasSenderOverride $currentRule.ExceptIfHasSenderOverride -ExceptIfHeaderContainsWords $currentRule.ExceptIfHeaderContainsWords -ExceptIfHeaderMatchesPatterns $currentRule.ExceptIfHeaderMatchesPatterns -ExceptIfMessageSizeOver '0' -ExceptIfMessageTypeMatches $currentRule.ExceptIfMessageTypeMatches`
                    -ExceptIfProcessingLimitExceeded $currentRule.ExceptIfProcessingLimitExceeded -ExceptIfRecipientADAttributeContainsWords $currentRule.ExceptIfRecipientADAttributeContainsWords -ExceptIfRecipientADAttributeMatchesPatterns $currentRule.ExceptIfRecipientADAttributeMatchesPatterns -ExceptIfRecipientDomainIs $currentRule.ExceptIfRecipientDomainIs`
                    -ExceptIfSenderADAttributeContainsWords $currentRule.ExceptIfSenderADAttributeContainsWords -ExceptIfSenderADAttributeMatchesPatterns $currentRule.ExceptIfSenderADAttributeMatchesPatterns -ExceptIfSenderDomainIs $currentRule.ExceptIfSenderDomainIs -ExceptIfSenderIPRanges $currentRule.ExceptIfSenderIPRanges -ExceptIfSentTo $currentRule.ExceptIfSentTo`
                    -ExceptIfSentToMemberOf $currentRule.ExceptIfSentToMemberOf -ExceptIfSubjectContainsWords $currentRule.ExceptIfSubjectContainsWords -ExceptIfSubjectMatchesPatterns $currentRule.ExceptIfSubjectMatchesPatterns -ExceptIfSubjectOrBodyContainsWords $currentRule.ExceptIfSubjectOrBodyContainsWords`
                    -ExceptIfSubjectOrBodyMatchesPatterns $currentRule.ExceptIfSubjectOrBodyMatchesPatterns -ExceptIfUnscannableDocumentExtensionIs $currentRule.ExceptIfUnscannableDocumentExtensionIs -ExceptIfWithImportance $currentRule.ExceptIfWithImportance -ExpiryDate $currentRule.ExpiryDate -From $currentRule.From`
                    -FromAddressContainsWords $currentRule.FromAddressContainsWords -FromAddressMatchesPatterns $currentRule.FromAddressMatchesPatterns -FromMemberOf $currentRule.FromMemberOf -FromScope $currentRule.FromScope -GenerateAlert $currentRule.GenerateAlert -GenerateIncidentReport $currentRule.GenerateIncidentReport`
                    -HasSenderOverride $currentRule.HasSenderOverride -HeaderContainsWords $currentRule.HeaderContainsWords -HeaderMatchesPatterns $currentRule.HeaderMatchesPatterns -IncidentReportContent $currentRule.IncidentReportContent -MessageSizeOver $ruleMessageSizeOver -MessageTypeMatches $currentRule.MessageTypeMatches`
                    -Moderate $currentRule.Moderate -ModifySubject $currentRule.ModifySubject -NonBifurcatingAccessScope $currentRule.NonBifurcatingAccessScope -NotifyAllowOverride $currentRule.NotifyAllowOverride -NotifyEmailCustomSubject $currentRule.NotifyEmailCustomSubject -NotifyEmailCustomText $currentRule.NotifyEmailCustomText`
                    -NotifyEndpointUser $currentRule.NotifyEndpointUser -NotifyOverrideRequirements $currentRule.NotifyOverrideRequirements -NotifyPolicyTipCustomText $currentRule.NotifyPolicyTipCustomText -NotifyPolicyTipCustomTextTranslations $currentRule.NotifyPolicyTipCustomTextTranslations`
                    -NotifyUser $currentRule.NotifyUser -NotifyUserType $currentRule.NotifyUserType -OnPremisesScannerDlpRestrictions $currentRule.OnPremisesScannerDlpRestrictions -PrependSubject $currentRule.PrependSubject -Priority $currentRule.Priority -ProcessingLimitExceeded $currentRule.ProcessingLimitExceeded`
                    -Quarantine $currentRule.Quarantine -RecipientADAttributeContainsWords $currentRule.RecipientADAttributeContainsWords -RecipientADAttributeMatchesPatterns $currentRule.RecipientADAttributeMatchesPatterns -RecipientDomainIs $currentRule.RecipientDomainIs -RedirectMessageTo $currentRule.RedirectMessageTo`
                    -RemoveHeader $currentRule.RemoveHeader -RemoveRMSTemplate $currentRule.RemoveRMSTemplate -ReportSeverityLevel $currentRule.ReportSeverityLevel -RestrictBrowserAccess $currentRule.RestrictBrowserAccess -RuleErrorAction $currentRule.RuleErrorAction -SenderADAttributeContainsWords $currentRule.SenderADAttributeContainsWords`
                    -SenderADAttributeMatchesPatterns $currentRule.SenderADAttributeMatchesPatterns -SenderAddressLocation $currentRule.SenderAddressLocation -SenderDomainIs $currentRule.SenderDomainIs -SenderIPRanges $currentRule.SenderIPRanges -SentTo $currentRule.SentTo -SentToMemberOf $currentRule.SentToMemberOf`
                    -SetHeader $currentRule.SetHeader -StopPolicyProcessing $currentRule.StopPolicyProcessing -SubjectContainsWords $currentRule.SubjectContainsWords -SubjectMatchesPatterns $currentRule.SubjectMatchesPatterns -SubjectOrBodyContainsWords $currentRule.SubjectOrBodyContainsWords -SubjectOrBodyMatchesPatterns $currentRule.SubjectOrBodyMatchesPatterns`
                    -ThirdPartyAppDlpRestrictions $currentRule.ThirdPartyAppDlpRestrictions -UnscannableDocumentExtensionIs $currentRule.UnscannableDocumentExtensionIs -WithImportance $currentRule.WithImportance -ErrorAction SilentlyContinue -ErrorVariable RuleErrors
            }
        }
        catch {
            Write-Output "ERROR: $_"
        }

        # Cleanup
        Write-Verbose "Cleaning up remote sessions and disconnecting"
        Get-PSSession | Remove-PSSession

        if ($RuleErrors -gt 0 -or $PolicyErrors -gt 0) {
            Write-Output "Errors detected!"
            foreach ($policyError in $PolicyErrors) {
                Write-Output "WARNING / ERROR: $policyError"
            }
            foreach ($ruleError in $RuleErrors) {
                Write-Output "WARNING / ERROR: $ruleError"
            }
        }
    }

    end {
        Write-Output "Finished!"
    }
}