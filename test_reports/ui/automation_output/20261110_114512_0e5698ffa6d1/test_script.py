async def run_test(page, output_dir, page_url):
    try:
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.wait_for_timeout(2000)
        await page.wait_for_selector('text=Análise com contexto.', timeout=10000)
        print('PASS: preview and dark auth screen loaded')
        await page.fill('input[placeholder="E-mail corporativo"]', 'debug-blue@example.com')
        await page.fill('input[placeholder^="Senha"]', 'BlueTeam123!')
        await page.get_by_text('Acessar workspace', exact=True).click(force=True)
        await page.wait_for_timeout(2500)
        print('Workspace visible:', await page.get_by_text('Pulso do SOC', exact=True).is_visible())
        print('Create action visible:', await page.get_by_text('Registrar incidente', exact=True).is_visible())
        await page.get_by_text('Registrar incidente', exact=True).first.click(force=True)
        await page.wait_for_timeout(300)
        print('Create modal visible:', await page.get_by_text('Novo incidente', exact=True).is_visible())
        await page.screenshot(path='/app/test_reports/ui/automation_output/20261110_114512_0e5698ffa6d1/workspace.jpeg', type="jpeg", quality=40, full_page=False)
        error_text = await page.evaluate("""() => { const errorElements = Array.from(document.querySelectorAll('.error, [class*="error"], [id*="error"]')); return errorElements.map(el => el.textContent).join(', '); }""")
        print('Errors:', error_text or 'none')
    except Exception as e:
        print(f'FINDING: auth/workspace flow failed: {e}')
        raise
