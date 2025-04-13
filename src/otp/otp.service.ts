import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { OTP } from './entities/otp.entity';
import { MoreThan, Repository } from 'typeorm';
import * as crypto from 'crypto';
import * as bcrypt from 'bcryptjs';
import { OTPType } from './type/otpType';
import { User } from 'src/user/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class OTPService {
  constructor(
    @InjectRepository(OTP)
    private otpRepository: Repository<OTP>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  //generate otp or reset link
  async generateToken(user: User, type: OTPType): Promise<string> {
    if (type === OTPType.OTP) {
      //generate 6 digit otp
      const otp = crypto.randomInt(100000, 999999).toString();
      const hashedOTP = await bcrypt.hash(otp, 10);
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

      //check if otp already exists for that user
      const existingOTP = await this.otpRepository.findOne({
        where: { user: { id: user.id }, type },
      });

      if (existingOTP) {
        //update exisiting token
        existingOTP.token = hashedOTP;
        existingOTP.expiresAt = expiresAt;
        await this.otpRepository.save(existingOTP);
      } else {
        //create otp entity
        const otpEntity = this.otpRepository.create({
          user,
          token: hashedOTP,
          type,
          expiresAt,
        });

        await this.otpRepository.save(otpEntity);
      }
      return otp;
    } else if (type === OTPType.RESET_LINK) {
      const resetToken = this.jwtService.sign(
        { id: user.id, email: user.email },
        {
          secret: this.configService.get<string>('JWT_RESET_SECRET'),
          expiresIn: '15m',
        },
      );

      return resetToken;
    }
  }

  //validating otp
  async validateOTP(userId: number, token: string): Promise<boolean> {
    const validToken = await this.otpRepository.findOne({
      where: {
        user: { id: userId },
        expiresAt: MoreThan(new Date()),
      },
    });

    if (!validToken) {
      throw new BadRequestException('OTP is expired, request a new one.');
    }

    const isMatch = await bcrypt.compare(token, validToken.token);

    if (!isMatch) {
      throw new BadRequestException('Invalid otp.Please try again');
    }

    return true;
  }

  //validate reset password link
  async validateResetPassword(token: string) {
    try {
      //verify the JWT token and decode it
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_RESET_SECRET'),
      });

      //return the user id extracted from token if verification succeeds
      return decoded.id;
    } catch (error) {
      //handle expired token
      if (error?.name === 'TokenExpiredError') {
        throw new BadRequestException(
          'The reset token has expired.Please request a new one',
        );
      }
      throw new BadRequestException('Invalid or malformed reset token');
    }
  }
}
