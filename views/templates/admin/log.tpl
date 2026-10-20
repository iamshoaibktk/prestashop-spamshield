{**
 * @author    iamshoaibktk@gmail.com (WhatsApp: +923459016286)
 * @license   https://opensource.org/licenses/AFL-3.0 Academic Free License 3.0 (AFL-3.0)
 *}
<div class="panel">
  <div class="panel-heading">
    <i class="icon-list"></i> {l s='Blocked attempts' d='Modules.Spamshield.Admin'}
    <span class="panel-heading-action">
      <a class="btn btn-default btn-sm" href="{$spamshield_clear_url|escape:'html':'UTF-8'}"
         onclick="return confirm('{l s='Clear the whole log?' d='Modules.Spamshield.Admin' js=1}');">
        <i class="icon-trash"></i> {l s='Clear log' d='Modules.Spamshield.Admin'}
      </a>
    </span>
  </div>

  <h4>{l s='Last 30 days' d='Modules.Spamshield.Admin'}</h4>
  {if $spamshield_stats}
    <p>
      {foreach $spamshield_stats as $stat}
        <span class="badge" style="margin-right:6px">{$stat.label|escape:'html':'UTF-8'}: {$stat.total|intval}</span>
      {/foreach}
    </p>
  {else}
    <p class="text-muted">{l s='Nothing blocked yet.' d='Modules.Spamshield.Admin'}</p>
  {/if}

  {if $spamshield_rows}
    <div class="table-responsive">
      <table class="table">
        <thead>
          <tr>
            <th>{l s='Date' d='Modules.Spamshield.Admin'}</th>
            <th>{l s='Form' d='Modules.Spamshield.Admin'}</th>
            <th>{l s='Reason' d='Modules.Spamshield.Admin'}</th>
            <th>{l s='IP address' d='Modules.Spamshield.Admin'}</th>
            <th>{l s='E-mail' d='Modules.Spamshield.Admin'}</th>
          </tr>
        </thead>
        <tbody>
          {foreach $spamshield_rows as $row}
            <tr>
              <td>{$row.date_add|escape:'html':'UTF-8'}</td>
              <td>{$row.form_label|escape:'html':'UTF-8'}</td>
              <td>{$row.reason_label|escape:'html':'UTF-8'}</td>
              <td>{$row.ip|escape:'html':'UTF-8'}</td>
              <td>{$row.email|escape:'html':'UTF-8'}</td>
            </tr>
          {/foreach}
        </tbody>
      </table>
    </div>
  {/if}
</div>
