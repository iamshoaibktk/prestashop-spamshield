{**
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 *}
<div class="panel">
  <div class="panel-heading"><i class="icon-book"></i> {l s='Documentation' d='Modules.Spamshield.Admin'}</div>
  <p>
    <a class="btn btn-primary" href="{$spamshield_doc_url|escape:'html':'UTF-8'}" target="_blank" rel="noopener">
      <i class="icon-file-pdf-o"></i> {l s='User guide (PDF)' d='Modules.Spamshield.Admin'}
    </a>
  </p>
  <p class="text-muted">
    {l s='Other languages:' d='Modules.Spamshield.Admin'}
    {foreach $spamshield_docs as $iso => $url}
      <a href="{$url|escape:'html':'UTF-8'}" target="_blank" rel="noopener">{$iso|upper|escape:'html':'UTF-8'}</a>{if !$url@last} · {/if}
    {/foreach}
  </p>
</div>
