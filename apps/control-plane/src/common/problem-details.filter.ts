import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { Response } from 'express';

/**
 * RFC 7807 Problem Details responses (API spec §2.3).
 * Every non-2xx response follows this shape, including a trace_id.
 */
@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<{ id?: string; path?: string; trace_id?: string }>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const typeByStatus: Record<number, string> = {
      400: 'bad-request',
      401: 'unauthenticated',
      403: 'forbidden',
      404: 'not-found',
      409: 'conflict',
      422: 'validation-failed',
      429: 'rate-limited',
      500: 'internal-error',
      503: 'service-unavailable',
    };

    let detail = 'Unexpected error.';
    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      detail =
        typeof body === 'string'
          ? body
          : ((body as Record<string, string>).detail ??
            (body as Record<string, string>).message ??
            detail);
    } else if (exception instanceof Error) {
      detail = exception.message;
    }

    const problem = {
      type: `https://docs.nexuspanel.io/errors/${typeByStatus[status] ?? 'internal-error'}`,
      title: titleFor(status),
      status,
      detail,
      instance: req?.path,
      trace_id: req?.trace_id ?? req?.id ?? 'unset',
    };

    res.status(status).header('Content-Type', 'application/problem+json').json(problem);
  }
}

function titleFor(status: number): string {
  const titles: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthenticated',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    422: 'Validation Failed',
    429: 'Rate Limited',
    500: 'Internal Error',
    503: 'Service Unavailable',
  };
  return titles[status] ?? 'Error';
}
