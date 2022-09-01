def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    if provides == 'list incidents':
        ctx_result['data'] = data
    else:
        ctx_result['data'] = data

    ctx_result['action'] = provides

    return ctx_result


def list_incidents(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'mssentinel_list_incidents.html'


