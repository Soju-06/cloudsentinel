import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../theme.dart';

/// A short, one-shot golf animation for the connection-error screen: a player
/// swings, the ball arcs across the fairway and rolls to a stop just short of
/// the hole — "so close, but the server did not answer".
///
/// It runs once and then rests, which keeps `pumpAndSettle`, battery use and
/// reduced-motion settings predictable. Increment [attempt] to replay it.
class GolfAttempt extends StatefulWidget {
  const GolfAttempt({
    super.key,
    this.attempt = 0,
    this.width = 340,
    this.height = 132,
  });

  /// Change this value to replay the swing (the RETRY button does this).
  final int attempt;
  final double width;
  final double height;

  @override
  State<GolfAttempt> createState() => _GolfAttemptState();
}

class _GolfAttemptState extends State<GolfAttempt>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1900),
  );

  bool _started = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (!_started) {
      _started = true;
      _play();
    }
  }

  @override
  void didUpdateWidget(GolfAttempt oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.attempt != oldWidget.attempt) {
      _play();
    }
  }

  void _play() {
    // Users who turn off animations get the final frame straight away.
    if (MediaQuery.maybeOf(context)?.disableAnimations ?? false) {
      _controller.value = 1;
      return;
    }
    _controller.forward(from: 0);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Semantics(
      label: 'A golf ball rolls to a stop just short of the hole',
      image: true,
      child: ExcludeSemantics(
        child: RepaintBoundary(
          child: SizedBox(
            width: widget.width,
            height: widget.height,
            child: CustomPaint(painter: _GolfPainter(_controller)),
          ),
        ),
      ),
    );
  }
}

class _GolfPainter extends CustomPainter {
  _GolfPainter(this.animation) : super(repaint: animation);

  final Animation<double> animation;

  /// Fractions of the timeline: swing, flight, bounce and roll.
  static const _flightStart = 0.12;
  static const _flightEnd = 0.60;
  static const _rollEnd = 0.92;

  double get _t => animation.value;

  @override
  void paint(Canvas canvas, Size size) {
    final t = _t;
    final u = size.height;
    final groundY = size.height * 0.83;
    final ballR = u * 0.033;

    _paintHorizon(canvas, size, groundY);
    _paintHole(canvas, size, groundY, t);
    _paintGolfer(canvas, size, groundY, t);
    _paintTrail(canvas, size, t, ballR);
    _paintBall(canvas, size, groundY, t, ballR);
    _paintCaption(canvas, size, t);
  }

  Offset _ballCenter(Size size, double groundY, double ballR, double t) {
    const teeX = 0.21;
    const landX = 0.745;
    const restX = 0.842;
    final restingY = groundY - ballR;

    if (t <= _flightStart) {
      return Offset(size.width * teeX, restingY);
    }

    if (t < _flightEnd) {
      final p = (t - _flightStart) / (_flightEnd - _flightStart);
      final eased = Curves.easeOutCubic.transform(p);
      final lift = math.sin(math.pi * p) * size.height * 0.30 * (1 - 0.22 * p);
      return Offset(
        size.width * (teeX + (landX - teeX) * eased),
        restingY - lift,
      );
    }

    final q = ((t - _flightEnd) / (_rollEnd - _flightEnd)).clamp(0.0, 1.0);
    final eased = Curves.easeOut.transform(q);
    final hop = q < 0.30
        ? math.sin(math.pi * (q / 0.30)) * size.height * 0.085
        : q < 0.55
        ? math.sin(math.pi * ((q - 0.30) / 0.25)) * size.height * 0.032
        : 0.0;
    return Offset(
      size.width * (landX + (restX - landX) * eased),
      restingY - hop,
    );
  }

  void _paintHorizon(Canvas canvas, Size size, double groundY) {
    // Faint green-room glow, as if a spotlight were pointed at the hole.
    final glow = Paint()
      ..shader =
          RadialGradient(
            colors: [
              AppColors.cyan.withValues(alpha: 0.10),
              AppColors.cyan.withValues(alpha: 0.0),
            ],
          ).createShader(
            Rect.fromCircle(
              center: Offset(size.width * 0.86, groundY - size.height * 0.12),
              radius: size.width * 0.42,
            ),
          );
    canvas.drawRect(Offset.zero & size, glow);

    final line = Paint()
      ..strokeWidth = 1
      ..shader = LinearGradient(
        colors: [
          AppColors.line.withValues(alpha: 0.0),
          AppColors.line.withValues(alpha: 0.55),
          AppColors.line.withValues(alpha: 0.0),
        ],
      ).createShader(Rect.fromLTWH(0, groundY, size.width, 1));
    canvas.drawLine(
      Offset(size.width * 0.04, groundY),
      Offset(size.width * 0.96, groundY),
      line,
    );
  }

  void _paintHole(Canvas canvas, Size size, double groundY, double t) {
    final center = Offset(size.width * 0.88, groundY);
    final rx = size.width * 0.026;
    final ry = size.height * 0.014;
    final rect = Rect.fromCenter(center: center, width: rx * 2, height: ry * 2);

    canvas.drawOval(
      Rect.fromCenter(center: center, width: rx * 2.9, height: ry * 3.2),
      Paint()
        ..color = AppColors.cyan.withValues(alpha: 0.16)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 6),
    );
    canvas.drawOval(rect, Paint()..color = const Color(0xFF01030A));
    canvas.drawOval(
      rect,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.2
        ..color = AppColors.cyan.withValues(alpha: 0.55),
    );

    // Flag pole and a pennant that settles when the ball stops.
    final top = Offset(center.dx, groundY - size.height * 0.44);
    canvas.drawLine(
      Offset(center.dx, groundY - ry * 0.5),
      top,
      Paint()
        ..strokeWidth = 1.6
        ..strokeCap = StrokeCap.round
        ..color = AppColors.muted.withValues(alpha: 0.85),
    );
    final flutter = math.sin(t * 24) * size.height * 0.014 * (1 - t);
    final flag = Path()
      ..moveTo(top.dx, top.dy)
      ..lineTo(
        top.dx + size.height * 0.125,
        top.dy + size.height * 0.052 + flutter,
      )
      ..lineTo(top.dx, top.dy + size.height * 0.108)
      ..close();
    canvas.drawPath(
      flag,
      Paint()..color = AppColors.cyan.withValues(alpha: 0.85),
    );
    canvas.drawPath(
      flag,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1
        ..color = AppColors.cyan.withValues(alpha: 0.9),
    );
  }

  void _paintGolfer(Canvas canvas, Size size, double groundY, double t) {
    final u = size.height;
    final gx = size.width * 0.085;
    final hip = Offset(gx, groundY - u * 0.25);
    final shoulder = Offset(gx, groundY - u * 0.45);
    final head = Offset(gx, groundY - u * 0.56);
    final hands = Offset(gx + u * 0.05, groundY - u * 0.36);

    final body = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = u * 0.024
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round
      ..color = AppColors.muted.withValues(alpha: 0.9);

    // Legs, torso, head and the lead arm.
    canvas.drawLine(hip, Offset(gx - u * 0.08, groundY), body);
    canvas.drawLine(hip, Offset(gx + u * 0.09, groundY), body);
    canvas.drawLine(hip, shoulder, body);
    canvas.drawLine(shoulder, hands, body);
    canvas.drawCircle(head, u * 0.052, Paint()..color = body.color);
    canvas.drawCircle(
      head,
      u * 0.052,
      Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = u * 0.014
        ..color = AppColors.background,
    );

    // Club: backswing (up and behind) to follow-through (down and ahead).
    final swing = Curves.easeOutCubic.transform((t / 0.18).clamp(0.0, 1.0));
    final angle = -2.45 + swing * 2.95;
    final tip = hands + Offset(math.cos(angle), math.sin(angle)) * (u * 0.34);
    final club = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = u * 0.014
      ..strokeCap = StrokeCap.round
      ..shader = const LinearGradient(colors: [AppColors.text, AppColors.cyan])
          .createShader(Rect.fromPoints(hands, tip));
    canvas.drawLine(hands, tip, club);

    // Motion arc while the club is still travelling.
    if (t < 0.26) {
      final arc = Paint()
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.2
        ..color = AppColors.cyan.withValues(alpha: 0.35 * (1 - t / 0.26));
      canvas.drawArc(
        Rect.fromCircle(center: hands, radius: u * 0.34),
        -2.45,
        math.max(0.001, angle + 2.45),
        false,
        arc,
      );
    }
  }

  void _paintTrail(Canvas canvas, Size size, double t, double ballR) {
    if (t <= _flightStart) return;
    for (var i = 1; i <= 7; i++) {
      final at = t - i * 0.021;
      if (at < _flightStart) break;
      final fade = (1 - i / 8) * 0.22;
      final center = _ballCenter(size, size.height * 0.83, ballR, at);
      canvas.drawCircle(
        center,
        ballR * (1 - i / 10),
        Paint()..color = AppColors.cyan.withValues(alpha: fade),
      );
    }
  }

  void _paintBall(
    Canvas canvas,
    Size size,
    double groundY,
    double t,
    double ballR,
  ) {
    final center = _ballCenter(size, groundY, ballR, t);
    final lift = (groundY - ballR - center.dy).clamp(0.0, size.height);
    final shadowFade = (1 - lift / (size.height * 0.55)).clamp(0.15, 1.0);

    canvas.drawOval(
      Rect.fromCenter(
        center: Offset(center.dx, groundY + 1.5),
        width: ballR * 2.1 * shadowFade,
        height: ballR * 0.75 * shadowFade,
      ),
      Paint()..color = Colors.black.withValues(alpha: 0.45 * shadowFade),
    );
    canvas.drawCircle(
      center,
      ballR * 1.9,
      Paint()
        ..color = AppColors.cyan.withValues(alpha: 0.20)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 5),
    );
    canvas.drawCircle(center, ballR, Paint()..color = const Color(0xFFF4FAFF));
    canvas.drawCircle(
      center.translate(-ballR * 0.3, -ballR * 0.3),
      ballR * 0.35,
      Paint()..color = Colors.white.withValues(alpha: 0.9),
    );

    // Small dust marks where the ball first lands.
    if (t > _flightEnd && t < _flightEnd + 0.16) {
      final fade = 1 - (t - _flightEnd) / 0.16;
      final land = Offset(size.width * 0.745, groundY - ballR);
      final dust = Paint()..color = AppColors.muted.withValues(alpha: fade);
      for (var i = 0; i < 4; i++) {
        final a = math.pi + i * (math.pi / 5);
        canvas.drawCircle(
          land + Offset(math.cos(a), math.sin(a)) * (ballR * 2.4),
          ballR * 0.22,
          dust,
        );
      }
    }
  }

  void _paintCaption(Canvas canvas, Size size, double t) {
    final fade = ((t - 0.78) / 0.16).clamp(0.0, 1.0);
    if (fade <= 0) return;
    final painter = TextPainter(
      text: TextSpan(
        text: 'SO CLOSE',
        style: TextStyle(
          color: AppColors.muted.withValues(alpha: 0.8 * fade),
          fontSize: size.height * 0.068,
          fontWeight: FontWeight.w700,
          letterSpacing: size.height * 0.028,
        ),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    painter.paint(
      canvas,
      Offset(
        (size.width - painter.width) / 2,
        size.height * 0.955 - painter.height / 2,
      ),
    );
  }

  @override
  bool shouldRepaint(_GolfPainter oldDelegate) => false;
}
